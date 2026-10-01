# Login 位址改為 localhost（已製作）

## 使用方式

已建立根目錄 `serverip.ini` 與 `Tartaros.local.exe`。原始 `Tartaros.bin` 保持不變。請直接啟動修改副本，工作目錄設為根目錄：

```powershell
Start-Process -FilePath 'D:\ttr\Tartaros.local.exe' -WorkingDirectory 'D:\ttr'
```

副本沒有修改 port、啟動模式、資源檢查或登入協定。現有資料仍缺資源，所以這不表示已可打開登入畫面；本次也沒有執行客戶端或觀察實際連線。若啟动器依然開啟原始 `Tartaros.bin`，它不會使用此修改副本。

## 確認的設定讀取方式

反組譯確認 VA `0x006ede70` 的函式呼叫 `GetPrivateProfileStringA`（IAT `0x00bd22bc`），參數節名是 `Login`、key 是 `IP`。VA `0x006edd50` 使用 `GetCurrentDirectoryA` 拼接反斜線與 `serverip.ini`，因此工作目錄要正確。

```ini
[Login]
IP=127.0.0.1
```

此設定分支位於 VA `0x004405c0` 所屬函式，當物件 mode 為 `0x40` 時使用設定檔。其他兩個分支 mode `0x52` 與 `0x54` 使用內建 IPv4；分別是 `35.161.134.244`、`218.146.198.4`。它們均呼叫 VA `0x00440850`，用 `%d.%d.%d.%d` 組成字串並寫入相同物件位址欄位。故單純建立 INI 不足以覆蓋這兩條分支。

分析也發現前一階段模式判定引用 `Rlyeh` 與其他常數，但未在本次實測命令列與 mode 選擇關係，因此沒有將猜測的參數加入啟動命令。

## 最小副本修改

`make_localhost.py` 驗證原始 SHA-256，再僅改兩條 IPv4 建構分支的立即數，不改指令長度、流程、PE 版面或 mode。各 IPv4 由四個立即數重建成 `127.0.0.1`，總共 8 個 byte 改變。

| 檔案 offset | 原 bytes | 新 bytes |
|---|---|---|
| `0x3fae5` | f4 00 00 00 | 01 00 00 00 |
| `0x3faea` | 23 | 00 |
| `0x3faec` | 86 | 00 |
| `0x3faee` | a1 | 7f |
| `0x3fb2d` | 04 | 01 |
| `0x3fb2f` | da 00 00 00 | 00 00 00 00 |
| `0x3fb34` | c6 | 00 |
| `0x3fb36` | 92 | 7f |

原始 SHA-256：`9741d1975327b9309d82b52f631165bc410757694d7c183a5eed970a53ebef91`。

副本 SHA-256：`2ba82f13e2a46179503424889a72cbea59d8c595c07cdea6535e0dd6a7f757c7`。

原始 Integrity 仍描述原始主程式；若檢查修改副本內容或檔名，可能拒絕載入。本次未改完整性清單或繞過檢查。此修改覆蓋已找到的初始 Login 位址三條分支，不保證登入後由伺服器下發的 Bridge／Game 位址也被改寫。

## 驗證與重現

```powershell
python .\anal\make_localhost.py
python .\anal\verify_localhost.py
```

已通過：原檔 hash 保護、逐 offset 原 bytes 檢查、副本同長度、反組譯兩分支立即數還原皆為 `127.0.0.1`，以及實際呼叫 Windows `GetPrivateProfileStringA` 確認 INI 回傳 `127.0.0.1`。沒有進行遊戲程序或網路動態驗證。

`localhost-disassembly.txt` 保存原始程式相關反組譯；`localhost-patch.json` 保存修改位置與 hash；Capstone 5.0.9 安裝在 `anal/python_deps`，用於分析及驗證，製作副本的腳本不需要此套件。

要恢復原版，使用原始 `Tartaros.bin`，並把新增的 `serverip.ini` 移離客戶端工作目錄即可。若要成功登入，仍需解析 port 並提供相容的本地服務。

