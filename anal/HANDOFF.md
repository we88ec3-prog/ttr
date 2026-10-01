# 跨電腦接續與目前狀態

- 原始客戶端：Tartaros Rebirth，Windows x86，清單 Build 45214。
- 原始 Tartaros.bin 未修改；Tartaros.local.exe 是 localhost 修改副本。
- serverip.ini 已确认 [Login] IP=127.0.0.1；另修改 mode 0x52 / 0x54 的兩組硬編碼 IPv4，共 8 bytes。
- 已有 make_localhost.py、verify_localhost.py 及 04-localhost-change.md。
- 版本清單 6504 檔，26 檔校驗符合、6478 檔缺少，尤其缺 UI 資源。數字為初次比對狀態。
- 實際啟動已產生二進位 Tartaros.cfg；log.txt 只記錄缺少文字 key kTiosConverterExpInfo。
- 第一個找不到的檔案尚未動態確認。Frida 下載失敗；trace_runtime_files.py 是準備中的追蹤腳本，尚未成功執行，不要當成追蹤成果。
- 最近一次已確認推送 commit 350cf04 至 origin/main；此後新增內容需另行提交推送。Git 不包含 Codex 聊天紀錄。

## 網路分析新增發現

主程式 VA 0x00806ad0 的連線函式：0x00806b65 呼叫 Winsock htons（ordinal 9），port 從呼叫參數 [ebp+0xc] 取得；0x00806b7c 呼叫 WSASocketA，family=2（AF_INET）、type=1（SOCK_STREAM）、protocol=0；0x00806b8c 呼叫 connect（ordinal 4），sockaddr 長度 16。因此這條路徑使用 IPv4 TCP，但實際 port 值仍需追蹤上層呼叫或執行期參數。此證據不排除其他模組或路徑使用 UDP。

遊戲應用層封包格式、握手、登入 opcode、加密方式尚未解析。Winsock/TCP 實作已在現有主程式中，不需要先取得所有圖形資源才能做靜態分析。port 可來自常數、表格或伺服器回覆，目前未確定來源，不能認定一定在缺少的檔案內。

分析腳本 inspect_network_calls.py 為探索用，部分片段起點未對齊指令，且 ordinal 篩選未限制來源 DLL。判讀需採用已對齊的 WS2_32 呼叫區段，不能將所有列印內容視為有效函式反組譯。

## 換電腦後給 Codex 的接續提示

請先讀取 anal/README.md、anal/04-localhost-change.md、anal/HANDOFF.md，延續客戶端分析。下一步追蹤 Login port 的來源與第一個實際缺檔，不重新修改已驗證的 localhost 副本。所有已確認結果與未驗證推測分開記錄至 anal。
