# Tartaros Rebirth 客戶端本地啟動解析

分析日期：2026-10-01。對象：`D:\ttr` 現有 34 個根目錄檔案。採用靜態分析，未執行遊戲、安裝元件、修改客戶端或連線原營運站點。

## 結論

這是 Windows x86 的 Tartaros Rebirth 客戶端片段。`Tartaros.exe` 是更新啟動器，`Tartaros.bin` 才是 PE 格式遊戲主程式。可以在補齊資源後嘗試直接建立主程式程序，但**目前不能宣稱能到登入畫面，更不能宣稱能離線遊玩**。

目前最明確的阻礙是缺檔：解壓後的原始完整性清單列出 6,504 個檔案，共 3,329,394,162 bytes（約 3.10 GiB）。現有 26 個清單內檔案大小與 MD5 全數吻合，缺少 6,478 個。這是對此版本清單的比對，並非所有缺檔都必須在開機第一步載入；也不包含清單外的動態生成檔案。

此外，登入、角色與世界流程依賴網路服務。本地程序啟動和本地伺服器可玩是兩個不同完成階段，改成 localhost 並不會產生所需的伺服器邏輯。

## 閱讀順序

- [啟動入口、依賴與實作路線](01-local-startup.md)
- [完整資源比對](02-resource-audit.md)：逐檔預期大小與狀態。
- [封裝、腳本及網路線索](03-formats-and-network.md)
- [Login 改 localhost：已製作副本與設定](04-localhost-change.md)：後續反組譯已確認 `[Login] IP`，並覆蓋兩個內建初始位址分支；較早文件中的格式未知描述屬第一階段狀態。

## 可重現分析

在 `D:\ttr` 執行：

```powershell
python .\anal\inspect_client.py
python .\anal\audit_resources.py
```

兩支腳本僅使用 Python 標準函式庫，讀取根目錄檔案並將輸出寫入 `anal`。PE 解析器針對此批 x86 樣本設計，不是通用或防惡意檔案解析器。

證據：`inventory.json` 保存 SHA-256、檔頭、PE 區段與靜態匯入；`manifest-audit.json` 保存清單 MD5 比對；`Integrity.decoded.xml` 是解壓原文，保留 euc-kr 編碼；`*.strings.txt` 的前欄為十六進位**檔案偏移**，不是虛擬位址。`*.xor-ff.strings.txt` 是封裝反相後的文字線索，不是完整解包。
