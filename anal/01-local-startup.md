# 本地啟動入口與必要條件

## 程式角色

| 檔案 | 已確認資訊 | 啟動意義 |
|---|---|---|
| Tartaros.exe | PE x86；含 `TartarosPatch`、`PatchClient2.pdb`、HTTP 更新及 `CreateProcessW` | 更新器，停服後可能卡在更新資訊下載 |
| Tartaros.bin | PE x86；含場景、Lua、D3D、音效與 Winsock 程式內容 | 遊戲主程式，副檔名不影響其 PE 性質 |
| Tartaros Rebirth.lnk | 文字證據指向 `E:\Tartaros\ins\Tartaros.exe` 與舊工作目錄 | 原捷徑不可當成現有路徑的有效入口 |
| TartarosKR.ini | 986 bytes 二進位資料 | 無法用一般 INI 編輯器可靠修改 |
| Integrity.xml | 自訂 EX 封裝加 zlib，成功解壓 | 版本與資源清單來源 |
| Master.stp | STPD 封裝；反相可讀出多個資源包路徑 | 存在此檔不代表角色、地圖包已包含在其中 |

版本清單：PackageVersion 2800、PatchClientVersion 1、MajorVersion 1、MinorVersion 1、Build 45214。`log.txt` 記錄 Rev. 45214，建置時間 Sep 21 2017 20:32:57，2017-10-17 曾到 `FIRS` → `LOGI`。這是舊環境記錄，不是現有資料夾的啟動驗證。`Tartaros.log` 另有 Rev. 45155 的 2017-09-12 breakpoint 崩潰，不能直接歸因於目前版本或目前缺檔。

## 第一階段：補齊客戶端

優先取得與 Build 45214 相符的完整資源及資料夾結構，依 `02-resource-audit.md` 驗證。尤其缺少 `UI/Component.stp`、`UI/ImageSets.stp`、`UI/Texture.stp`、`UI/StringTable.stp`、`UI/Font.stp`、`UI/LUA.stp`、`UI/Font/*.ttf`，以及大量 Character、地圖、音效資料。主程式明確含有 UI 包載入路徑，補零長度檔案不能替代有效資源。

保留同版 `Integrity.xml`、`Master.stp` 與其他資源的一致性，避免混用不同版清單。現有根目錄 26 個清單內檔案全數符合 MD5；現階段沒有證據需要修補它們。

## 第二階段：直接啟動測試

補齊資源後，在可回復的 Windows 測試環境，把工作目錄指定為客戶端根目錄。以下是**待驗證的測試命令**，本次沒有執行；未確認主程式是否還要求啟動器參數或特殊初始化。

```powershell
$clientRoot = 'D:\ttr'
Start-Process -FilePath "$clientRoot\Tartaros.bin" -WorkingDirectory $clientRoot -WindowStyle Hidden -PassThru
```

此命令要求 Windows 建立 PE 程序；若介面出現而需互動，可在下一次受控測試改用一般視窗模式。不要透過 Shell 檔案關聯「開啟 .bin」，也不要把改副檔名當成處理缺檔的方式。若直接建立程序失敗，記錄 Win32 錯誤、程序是否立即退出、新增日誌及缺檔路徑，再追蹤啟動器的 `CreateProcessW` 呼叫；目前沒有已確認可用的命令列旗標。

先驗證程序載入，再驗證圖形初始化，最後才是登入介面與網路。以新寫入的 `log.txt`／`Tartaros.log` 時間及內容判斷進度，勿引用舊日誌作為成功證據。

## 執行依賴

- 遊戲及啟動器 machine 均為 `0x14c`（x86）。相關執行元件必須與 x86 相符。
- 主程式靜態匯入 `d3dx9_32.dll`、`ijl15.dll`、`libvorbisfile.dll`、`OpenAL32.dll`，這些根目錄檔案存在。亦有 DirectInput8、DirectDraw、WinMM、Winsock 等 Windows 元件匯入。
- `Network.dll` 靜態匯入 `MSVCP80.dll`、`MSVCR80.dll`；若實際載入它，需對應 VC++ 2005 x86 runtime／SxS 組態。這不代表主程式一定動態使用該 DLL；它沒有列於主程式靜態匯入表。
- D3D 匯入與舊日誌證實 DirectX 9 時代渲染路徑；是否還有動態載入依賴須以實測確認，不應僅憑靜態匯入表認定依賴已完整。
- 主程式 PDB 字串 `G:\BUILD\GSP\Client\ClientBuild\Win32\Optimized Release (Without NProtect)\Tartaros.pdb` 是無 NProtect 建置的強線索；靜態匯入沒有 GameGuard DLL。根目錄仍存在 `GameGuard.des`，不能據此認定必須啟動防外掛，也不能只憑 PDB 字串保證所有防外掛檢查不存在。

## 第三階段：本地伺服器

要在本機登入及遊玩，仍需相容的伺服器程式或重新實作協定。現有資料未見伺服器可執行檔、資料庫結構或伺服器原始碼。

建議順序：定位 serverIp 設定讀取函式 → 確認位址、port 與設定格式 → 讓客戶端連到本地測試服務 → 解析首個封包及握手 → 實作版本檢查、登入、伺服器清單 → 再處理角色、場景、戰鬥與持久化。Auth、Login、Bridge、Game／Area 是文字線索顯示的邏輯角色，不代表已確認必須有同數量的獨立程序。

目前無法提供可信的 `serverip.ini` 範本、port 或可玩服務端。這些欄位需要交叉參照與受控網路觀測；不能用猜測的 `[Login] IP=127.0.0.1` 取代分析。

