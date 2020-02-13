#include <Windows.h>
#include <process.h>

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <list>

namespace Log {
	namespace Out {
		void WriteLineW(const wchar_t* title, const wchar_t* type, const wchar_t* content) {
			std::wcout << L"[" << title << L"]" << L" ";
			if (*type != L'\0')
				std::wcout << type << L"：";
			std::wcout << content << std::endl;
		}
	}

	namespace Err {
		void WriteLineW(const wchar_t* title, const wchar_t* type, const wchar_t* content) {
			std::wcerr << L"[" << title << L"]" << L" ";
			if (*type != L'\0')
				std::wcerr << type << L"：";
			std::wcerr << content << std::endl;
		}
	}
}

namespace Core {
	namespace Type {
		using VA = UINT64;
		using RVA = UINT32;
	}

	enum class ErrorCode : int {
		ERR_SUCCESS,
		ERR_CREATEPIPE_FAILED,
		ERR_CREATEPROCESS_FAILED,
		ERR_CREATEREMOTETHREAD_FAILED,
		ERR_VIRTUALALLOC_FAILED,
		ERR_WRITEPROCESSMEMORY_FAILED,
		ERR_FILE_OPEN_FAILED,
		ERR_MALLOC_FAILED,
		ERR_PATHCCHREMOVEFILESPEC_FAILED
	};

	namespace Process {
		namespace Local {
			template<typename T_STRING>
			ErrorCode GetCommandOutput(LPWSTR lpcmd, T_STRING& output) {
				SECURITY_ATTRIBUTES sa;
				HANDLE hRead, hWrite;
				sa.nLength = sizeof(SECURITY_ATTRIBUTES);
				sa.lpSecurityDescriptor = NULL; //使用系统默认的安全描述符  
				sa.bInheritHandle = TRUE; //创建的进程继承句柄  

				if (!CreatePipe(&hRead, &hWrite, &sa, 0))
					return ErrorCode::ERR_CREATEPIPE_FAILED;

				STARTUPINFO si;
				PROCESS_INFORMATION pi;

				ZeroMemory(&si, sizeof(si));
				ZeroMemory(&pi, sizeof(pi));

				si.cb = sizeof(STARTUPINFO);
				GetStartupInfo(&si);
				//si.hStdError = hWrite;
				si.hStdOutput = hWrite; //新创建进程的标准输出连在写管道一端  
				si.wShowWindow = SW_HIDE; //隐藏窗口  
				si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

				if (!CreateProcess(NULL, lpcmd, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
					return ErrorCode::ERR_CREATEPROCESS_FAILED;
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
				CloseHandle(hWrite);

				BYTE buffer[4096] = { 0 };
				DWORD bytesRead;
				output = "";
				while (ReadFile(hRead, buffer, 4092, &bytesRead, NULL) != NULL) {
					output.append(static_cast<typename T_STRING::value_type*>(buffer),
						bytesRead / sizeof(typename T_STRING::size_type));
				}
				CloseHandle(hRead);
				return ErrorCode::ERR_SUCCESS;
			}
		}

		namespace Remote {
			template<typename T>
			ErrorCode RunThread(HANDLE hProcess, LPVOID lpThreadProc, T lpParameter, DWORD& exitcode) {
				auto ret = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpThreadProc), (LPVOID)lpParameter, NULL, NULL);
				if (ret == NULL)
					return ErrorCode::ERR_CREATEREMOTETHREAD_FAILED;
				WaitForSingleObject(ret, INFINITE);
				GetExitCodeThread(ret, &exitcode);
				CloseHandle(ret);
				return ErrorCode::ERR_SUCCESS;
			}

			template<typename T_STRING>
			ErrorCode RunThreadWithString(HANDLE hProcess, LPVOID lpLoadLibrary, T_STRING& library_path, DWORD& exitcode) {
				auto str = library_path;
				auto len = (str.length() + 1) * sizeof(typename T_STRING::value_type);
				auto lpstr = VirtualAllocEx(hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (lpstr == nullptr) {
					return ErrorCode::ERR_VIRTUALALLOC_FAILED;
				}
				if (!WriteProcessMemory(hProcess, lpstr, (LPVOID)(str.c_str()), len, NULL)) {
					VirtualFreeEx(hProcess, lpstr, 0, MEM_RELEASE);
					return ErrorCode::ERR_WRITEPROCESSMEMORY_FAILED;
				}
				HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpLoadLibrary), lpstr, NULL, NULL);
				if (hRemoteThread == NULL) {
					VirtualFreeEx(hProcess, lpstr, 0, MEM_RELEASE);
					return ErrorCode::ERR_CREATEREMOTETHREAD_FAILED;
				}
				WaitForSingleObject(hRemoteThread, INFINITE);
				GetExitCodeThread(hRemoteThread, &exitcode);
				CloseHandle(hRemoteThread);
				VirtualFreeEx(hProcess, lpstr, 0, MEM_RELEASE);
				return ErrorCode::ERR_SUCCESS;
			}
		}
	}
}

std::wstring GetFileName(std::wstring path) {
	if (path.empty())
		return L"";
	std::wstring::size_type iPos = path.find_last_of(L'\\') + 1;
	return path.substr(iPos, path.length() - iPos);
}

std::wstring GetDirectory(std::wstring path) {
	if (path.empty())
		return L"";
	if (path.back() == L'\\')
		path.resize(path.size() - 1);
	auto pos = path.rfind(L"\\");
	if (std::string::npos != pos)
		return path.substr(0, pos);
	return L"";
}

std::wstring Append(std::wstring a, std::wstring b) {
	if (a.empty())
		return b;
	if (a.back() == L'\\')
		return a + b;
	else
		return a + L"\\" + b;
}

constexpr wchar_t const* pHelpStr =
L""
"用法：nanolauncher.exe [选项]... BDS主程序路径\n"
"\n"
"启动BDS主程序并允许同时加载插件。\n"
"\n"
"选项\t\t\t\t意义\n"
"-h, --help\t\t\t显示帮助信息并退出\n"
"-p <插件路径>...\t\t设置要加载的单个插件或多个插件的路径\n"
"-r [次数]\t\t\t启动BDS异常退出后的自动重启功能，并设置重启次数，设置为-1为不限次数。如不提供次数则设置为3次。\n"
"\n"
"请注意：\n"
"BDS主程序和插件的路径为文件绝对路径或者相对于本启动器所在目录的相对路径。\n"
"插件针对的目标BDS版本与当前BDS版本必须完全一致，否则请勿加载该插件！\n"
"\n"
"例：nanolauncher.exe -r 5 -p .\\plugin1.dll .\\plugin2.dll C:\\BDS\\bedrock_server.exe\n"
"";

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
	auto localloc = std::locale::global(std::locale(""));
	// 处理特殊情况
	std::wstring bdsexec;
	if (argc >= 2) {
		std::wstring h1(L"-h"), h2(L"--help"), h3(L"/?");
		if (h1.compare(argv[1]) == 0 || h2.compare(argv[1]) == 0 || h3.compare(argv[1]) == 0) {
			std::wcout << pHelpStr;
			return 0;
		}
		else if (argv[argc - 1][0] == L'-') {
			Log::Err::WriteLineW(L"启动器", L"错误", L"未提供BDS主程序文件路径！");
			return 1;
		}
		bdsexec = argv[argc - 1];
	}
	else {
		Log::Err::WriteLineW(L"启动器", L"错误", L"参数数量不正确！您可以使用/?或-h参数查看本启动器的帮助内容。");
		return 2;
	}
	// 整理选项
	std::list<std::pair<std::wstring, std::list<std::wstring>>> options;
	for (int i = 1; i < argc - 1; ++i) {
		if (argv[i][0] == L'-' && (argv[i][1] != L'\0' && (argv[i][1] < L'0' || argv[i][1] > L'9'))) {
			options.emplace_back(argv[i], std::list<std::wstring>());
		}
		else {
			if (!options.empty()) {
				options.back().second.emplace_back(argv[i]);
			}
		}
	}
	// 分析选项
	std::list<std::wstring> plugin_list;
	bool willRetry = false, nostop = false;
	int retry = 1;
	for (auto op_it = options.cbegin(); op_it != options.cend(); ++op_it) {
		if (op_it->first == L"--plugin" || op_it->first == L"-p") {
			for (auto ws_it = op_it->second.cbegin(); ws_it != op_it->second.cend(); ++ws_it) {
				plugin_list.push_back(*ws_it);
			}
		}
		else if (op_it->first == L"--retry" || op_it->first == L"-r") {
			for (auto ws_it = op_it->second.cbegin(); ws_it != op_it->second.cend(); ++ws_it) {
				willRetry = true;
				int times = std::stoi(*ws_it);
				if (times == -1)
					nostop = true;
				retry += times;
			}
			if (!willRetry) {
				willRetry = true;
				retry = 3;
			}
		}
	}
	// 获取BDS目录
	std::wstring bdspath = GetDirectory(bdsexec);
	if (bdspath.empty()) {
		Log::Err::WriteLineW(L"启动器", L"错误", L"BDS主程序路径错误！");
		return 3;
	}
	// 准备加载插件
	auto hmKernel32dll = GetModuleHandleW(L"kernel32.dll");
	if (hmKernel32dll == NULL) {
		Log::Err::WriteLineW(L"启动器", L"错误", L"系统环境异常，找不到模块kernel32.dll！");
		return 4;
	}
	LPVOID lpSetConsoleCP = GetProcAddress(hmKernel32dll, "SetConsoleCP");
	LPVOID lpSetConsoleOutputCP = GetProcAddress(hmKernel32dll, "SetConsoleOutputCP");
	LPVOID lpLoadLibraryW = GetProcAddress(hmKernel32dll, "LoadLibraryW");
	// 重启循环
	for (; retry > 0 || nostop; --retry) {
		DWORD exitcode;
		// 启动进程
		STARTUPINFO stif = { 0 };
		PROCESS_INFORMATION psif = { 0 };
		stif.cb = sizeof(stif);
		BOOL ret = CreateProcessW(bdsexec.c_str(), NULL, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED, NULL,
			NULL/*bdspath.c_str()*/, &stif, &psif);
		if (ret != TRUE) {
			Log::Err::WriteLineW(L"启动器", L"错误", L"启动BDS失败！");
			return 5;
		}
		Log::Out::WriteLineW(L"启动器", L"信息", L"BDS启动。");
		// 设置BDS控制台字符集为UTF-8
		Core::Process::Remote::RunThread(psif.hProcess, lpSetConsoleCP, reinterpret_cast<LPVOID>(CP_UTF8), exitcode);
		Core::Process::Remote::RunThread(psif.hProcess, lpSetConsoleOutputCP, reinterpret_cast<LPVOID>(CP_UTF8), exitcode);
		// 加载插件
		std::wstring plugin;
		for (auto it = plugin_list.begin(); it != plugin_list.end(); ++it) {
//			if (it->front() == L'.') {
//				std::wstring x = TEXT(".\\");
//				plugin = Append(x, *it);
//			}
//			else
				plugin = *it;
			auto err = Core::Process::Remote::RunThreadWithString(psif.hProcess, lpLoadLibraryW, plugin, exitcode);
			std::wstring ws = L"加载插件" + GetFileName(plugin) + L"。";
			if (err == decltype(err)::ERR_SUCCESS && exitcode != NULL)
				Log::Out::WriteLineW(L"启动器", L"信息", ws.c_str());
			else
				Log::Err::WriteLineW(L"启动器", L"错误", (L"无法" + ws).c_str());
		}
		// 等待进程关闭
		ResumeThread(psif.hThread);
		CloseHandle(psif.hThread);
		WaitForSingleObject(psif.hProcess, INFINITE);
		GetExitCodeProcess(psif.hProcess, &exitcode);
		CloseHandle(psif.hProcess);
		if (exitcode == 0) {
			Log::Out::WriteLineW(L"启动器", L"信息", L"BDS正常退出。");
			Log::Out::WriteLineW(L"启动器", L"信息", L"启动器退出。");
			return 0;
		}
		if ((willRetry && retry > 0) || nostop)
			Log::Err::WriteLineW(L"启动器", L"警告", L"BDS异常退出，将重新拉起！");
		else
			Log::Err::WriteLineW(L"启动器", L"警告", L"BDS异常退出！");
	}
	if (willRetry)
		Log::Err::WriteLineW(L"启动器", L"错误", L"由于重新拉起次数用完，启动器不再重新拉起BDS！");
	Log::Out::WriteLineW(L"启动器", L"信息", L"启动器退出。");
	return 0;
}

