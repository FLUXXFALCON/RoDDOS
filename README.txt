# Roblox Sunucu Çökertici (Anonim DDoS+DoS+Exploit+Kendinden Enjektör)

Bu Python betiği, Roblox sunucularına karşı çeşitli ağ saldırıları ve istismarları gerçekleştirmek için tasarlanmıştır. Tor ve I2P aracılığıyla anonimlik, MAC adresi sahteciliği ve Roblox'a Lua betiklerinin kendiliğinden enjekte edilmesi gibi özellikleri içerir.

**⚠️ UYARI: Bu araç yalnızca eğitim amaçlıdır. İzinsiz kullanım yasa dışı ve etik dışıdır. Yazar, herhangi bir kötüye kullanımdan sorumlu değildir.**

## Özellikler

* **MAC Sahteciliği:** Artan anonimlik için MAC adresinizi değiştirir.
* **Tor ve I2P Desteği:** Gelişmiş gizlilik için ağ trafiğini Tor ve I2P üzerinden yönlendirir.
* **Roblox Sunucu Keşfi:** Belirli bir Roblox Yer Kimliği için etkin sunucu listelerini getirir.
* **Sunucu IP Tespiti:** Roblox sunucu IP'lerini tanımlamak için ağ trafiğini yakalar.
* **UDP Sel Saldırısı (DDoS):** Sunucuyu aşırı yüklemek için yüksek hacimli UDP paketleri gönderir. Sahteciliği ve I2P'yi destekler.
* **TCP Slowloris Saldırısı (DoS):** Sunucu kaynaklarını tüketmek için çok sayıda yavaş HTTP bağlantısı açar ve sürdürür. Tor'u kullanır.
* **Güvenlik Açığı Taraması:** Nmap kullanarak hedef IP'leri açık bağlantı noktaları ve bilinen güvenlik açıkları için tarar.
* **İstismar Girişimleri:** Sunucuyu çökertmek için tanımlanan güvenlik açıklarından yararlanmaya çalışır.
* **Lua Betik Enjeksiyonu:** Sunucu istikrarsızlığına neden olmak için çalışan bir Roblox örneğine bir Lua betiği enjekte eder.
* **Renkli Konsol Çıktısı:** Net ve bilgilendirici geri bildirim sağlar.

## Ön Koşullar

* Python 3.x
* Gerekli Python kitaplıkları: `scapy`, `psutil`, `requests`, `json`, `nmap`, `stem`, `socks`

    ```bash
    pip install scapy psutil requests nmap pysocks stem
    ```

* Yönetici ayrıcalıkları (MAC sahteciliği ve işlem enjeksiyonu için gereklidir).
* Tor yüklü ve çalışır durumda (Tor işlevselliği kullanılıyorsa).
* I2P yüklü ve çalışır durumda (I2P işlevselliği kullanılıyorsa).
* Nmap yüklü ve sisteminizin PATH'inde.

## Kurulum

1.  **Bağımlılıkları Yükleyin:** Gerekli Python kitaplıklarını yüklemek için yukarıdaki `pip install` komutunu çalıştırın.
2.  **Tor ve I2P:** Anonimlik özelliklerini kullanmayı düşünüyorsanız Tor ve I2P'nin yüklü ve çalışır durumda olduğundan emin olun.
3.  **Yönetici Ayrıcalıkları:** Betiği yönetici olarak çalıştırın.

## Kullanım

1.  Yonetici cmd acin ve py roblox_server_dos(beta).py yaziniz.
2.  Betik, Roblox Yer Kimliğini girmenizi isteyecektir.
3.  Görüntülenen listeden hedeflemek istediğiniz sunucuyu seçin.
4.  Roblox'ta seçilen sunucuya katılın.
5.  Betik, sunucu IP'lerini tarayacak ve saldırıları başlatacaktır.
6.  Ekrandaki talimatları ve uyarıları izleyin.

## Önemli Notlar

* **Etik Kullanım:** Bu araç yalnızca sahip olduğunuz veya test etmek için açık izniniz olan sunucularda kullanılmalıdır.
* **Anonimlik:** Tor, I2P ve MAC sahteciliği bir miktar anonimlik sağlarken, bunlar kusursuz değildir. Dikkatli olun.
* **Roblox Güncellemeleri:** Roblox güncellemeleri betiğin işlevselliğini bozabilir.
* **Güvenlik Duvarı/Antivirüs:** Güvenlik duvarınızın veya antivirüs yazılımınızın betiğin ağ etkinliğini engellemediğinden emin olun.
* **Yönetici Hakları:** Betiği yönetici olarak çalıştırmak, MAC sahteciliği ve betik enjeksiyonu için gereklidir.
* **I2P Kurulumu:** I2P http proxy varsayılan olarak 4444 bağlantı noktasında ve udp proxy 4447 bağlantı noktasındadır.

## Kod Yapısı

* `ConsoleColors`: Renkli konsol çıktısı için sınıf.
* `is_admin()`: Betiğin yönetici ayrıcalıklarıyla çalışıp çalışmadığını kontrol eder.
* `spoof_mac()`/`restore_mac()`: MAC adresi sahteciliği ve geri yükleme işlevleri.
* `check_service_running()`: Bir hizmetin belirli bir ana bilgisayar ve bağlantı noktasında çalışıp çalışmadığını kontrol eder.
* `start_tor()`: Tor hizmetini başlatır.
* `setup_tor_and_i2p()`: Tor ve I2P proxy'lerini yapılandırır.
* `start_roblox()`/`is_roblox_running()`: Roblox işlemlerini yönetme işlevleri.
* `inject_local_script()`: Roblox'a bir Lua betiği enjekte eder.
* `is_private_ip()`: Bir IP adresinin özel bir aralıkta olup olmadığını kontrol eder.
* `get_roblox_servers()`: Roblox sunucu listelerini getirir.
* `udp_flood()`: Bir UDP sel saldırısı gerçekleştirir.
* `tcp_slowloris()`: Bir TCP Slowloris saldırısı gerçekleştirir.
* `scan_vulnerabilities()`: Nmap kullanarak güvenlik açıklarını tarar.
* `exploit_and_crash()`: Güvenlik açıklarından yararlanmaya çalışır.
* `detect_server_ips()`: Sunucu IP'lerini tespit etmek için ağ trafiğini yakalar.
* `injector_interface()`: Ana kullanıcı arayüzü.

## Sorumluluk Reddi

Bu betik, eğitim amaçlı olduğu gibi sağlanmıştır. Yazar, bu betikten kaynaklanan herhangi bir hasar veya kötüye kullanımdan sorumlu değildir. Sorumlu ve etik bir şekilde kullanın.
