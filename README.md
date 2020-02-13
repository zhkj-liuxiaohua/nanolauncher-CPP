# nanolauncher-CPP
带自动重启的命令提示符形式的MC插件启动器（源自player）

用法：nanolauncher.exe [选项]... BDS主程序路径

启动BDS主程序并允许同时加载插件。

选项                            意义
-h, --help                      显示帮助信息并退出
-p <插件路径>...                设置要加载的单个插件或多个插件的路径
-r [次数]                       启动BDS异常退出后的自动重启功能，并设置重启次数，设置为-1为不限次数。如不提供次数则设置 为3次。

请注意：
BDS主程序和插件的路径为文件绝对路径或者相对于本启动器所在目录的相对路径。
插件针对的目标BDS版本与当前BDS版本必须完全一致，否则请勿加载该插件！

例：nanolauncher.exe -r 5 -p .\plugin1.dll .\plugin2.dll C:\BDS\bedrock_server.exe
