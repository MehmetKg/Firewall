# Firewall
Bu proje, PyQt5 ve PyDivert kullanarak ağ güvenliğini artırmayı hedefleyen bir güvenlik duvarı (firewall) uygulamasıdır. Uygulama, TCP/UDP trafiğini izleyip engelleyebilir, belirli IP adresleri ve portlara kısıtlamalar getirebilir. Ayrıca, DDoS saldırılarını tespit etme ve web sitesi engelleme gibi önemli güvenlik özellikleri de sunar.

Özellikler:

Protokol Tanıma: TCP, UDP ve diğer ağ protokollerini tanıma ve filtreleme.

DDoS Tespiti: Anormal ağ trafiği tespit edilip, şüpheli IP adresleri kara listeye alınır.

Web Site Engelleme: Kullanıcılar, URL'leri IP'ye dönüştürerek engelleyebilir.

Gelişmiş Kural Yönetimi: IP adresi ve portlara dayalı kurallar eklenebilir.

Gerçek Zamanlı Trafik İzleme: Kaynak, hedef ve protokol bazında ağ trafiği görüntülenebilir.

Proje, WinDivert kütüphanesi aracılığıyla ağ paketlerini yakalayarak güvenlik işlemleri gerçekleştirir. Kullanıcılar, PyQt5 arayüzü üzerinden trafiği izleyebilir ve yönetebilir.

Gerekli Bağımlılıklar:

PyQt5

pydivert

socket

logging

Kullanım:

Projeyi yerel ortamınızda çalıştırın.

Yönetici izinleri ile uygulamayı başlatın (Windows için).

Firewall'u başlatıp, ağ trafiğini izlemeye başlayın.
