# 封裝、Lua 與網路分析重點

## Integrity.xml 已成功解析

檔案前 16 bytes 是 `45 58 00 00 7e 29 03 00 c1 35 0c 00 10 00 00 00`；offset `0x10` 開始為 `78 9c` zlib stream。直接 `zlib.decompress(data[16:])` 得到 XML，宣告 euc-kr 編碼。腳本先 decode euc-kr 再解析 ElementTree，避免內建 XML parser 的多位元組編碼限制。

XML `<PATCH>` 保存版本；巢狀 `<FOLDER name>` 與 `<FILE name Checksum FileLength>` 保存相對路徑、MD5 與大小。實際對 26 個現有清單檔案計算 MD5 全數吻合，支持 Checksum 是 MD5 的判讀。EX header 其他欄位尚未完整定義；不要把此單一樣本解碼方式泛化到所有封裝。

## STP 與其他資源

所有現有 `.stp` 前四 bytes 都是 ASCII `STPD`。部分資料 XOR `0xff` 可恢復有意義的文字，例如 `Master.stp` offset `0x410` 為 `Character/Cha/Base`，後續多個路徑以 `0x400` 間距出現。這支持索引資料存在反相處理與固定大小紀錄的假說，但尚未驗證紀錄結構、payload offset、壓縮演算法及完整抽取流程。

`pack.gms` 有 `_gbDefaultStateBlock`、`alphablend`、`lightmap` 等渲染狀態名稱，應與 G-Blender 材質／渲染狀態有關，並非從名稱就能認定是資源解包器。`fcs.flu` 頭部有 `CHA_ABF`、`*.abf` 線索，其正式格式未解析。

## Lua

`boot.lua`、`Logic.lua` 檔頭 `1b 4c 75 61 51` 為 Lua 5.1 bytecode。後續 header 表示 little-endian、4-byte int／size_t／instruction、8-byte number；不是可直接編輯的 Lua 原始碼。

`boot.lua` 可見 TRUE、FALSE、math、randomseed、os、time 常數；`Logic.lua` 很小，不能因此推論它包含完整遊戲規則。主程式包含 Lua API 與 `UI/LUA/LuaUtil.lua` 路徑，腳本是引擎的一部分，不能在外部 Lua runtime 單獨執行就得到遊戲。

## 設定與網路證據

| 主程式檔案偏移 | 字串 | 可支持的結論 |
|---|---|---|
| `0x7f95c0` | serverIp.ini | 有外部 serverIp 設定路徑線索 |
| `0x7f95d0` | Rlyeh | 鄰近常數，角色尚未確定 |
| `0x7f95d8` | 81F91496CFC348A89F5AF83CBCDCEAE8 | 32 位十六進位常數；尚不能認定是密鑰或 MD5 用途 |
| `0x7f95fc` | serverip.ini | 大小寫不同，在一般 Windows 路徑上通常對應同檔 |
| `0x7f9610` | Login | 可能是設定或邏輯標識；僅此不足以推出節名及 key |
| `0x7f9650` | %d.%d.%d.%d | IPv4 格式線索；需交叉參照確認用途 |
| `0x80401c` | Failed to connect game server | game 連線錯誤路徑 |
| `0x80403c` | Failed to connect bridge server | bridge 連線錯誤路徑 |
| `0x83f5f8` | packetlog.ini | 封包記錄設定線索；格式未知 |
| `0x83f690` | L%d Command [%04d] : | command 與封包記錄線索 |

`serverip.ini`、`Tartaros.cfg`、`packetlog.ini` 現在皆不存在。`TartarosKR.ini` 有高比例二進位內容與內嵌檔名字串，尚不知是加密、封裝或其他表示法；不能當純文字 INI 寫入。未從本次分析確認服務端 IP、port、封包 opcode、封包 framing 或加密協定。

下一步可在反組譯工具中把 file offset 經 PE 區段換算 RVA／VA，追蹤 `serverIp.ini` 的讀取及解析呼叫、`Login` 的引用，再跟到 Winsock 連線地址。主程式與 `Network.dll` 均有 Winsock 線索，不能只分析 DLL 就認定掌握全部通訊。先修復資源才能讓執行進度可靠地到達網路初始化。

## 本次驗證界線

已驗證：x86 PE 入口角色的多項字串／匯入證據、Integrity 解壓與 XML 解析、逐檔大小及 MD5、Lua bytecode header、STPD signature 與部分反相路徑。未驗證：主程式實際啟動、參數契約、現代 Windows 相容性、UI 顯示、服務端協定及離線遊玩。

