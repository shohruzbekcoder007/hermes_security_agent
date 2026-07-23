"""
O'zbekcha matnlar — toifa tavsifi, sabab, ta'sir, tavsiyalar.

Qoida ID yoki toifa nomi bo'yicha lokalizatsiya.
"""

from __future__ import annotations

from agents.nginx_analyzer.models import CategoryProfile, Severity

# rule_id -> (category_uz, description, root_cause, impact, recommendations)
_UZ_BY_RULE: dict[str, tuple[str, str, str, str, list[str]]] = {
    "modsec_anomaly": (
        "ModSecurity bloki",
        "Veb-ilova firewall (ModSecurity) xavfsizlik qoidalari asosida so'rovni rad etdi.",
        "So'rov ModSecurity/CRS qoidasiga tushgan (SQLi, XSS, skaner, protokol anomaliyasi va hokazo).",
        "Kutilgan bloklar bo'lsa ilovaga ta'sir yo'q; qoidalar qattiq bo'lsa qonuniy trafik ham bloklanishi mumkin (false positive).",
        [
            "ModSecurity audit logda rule ID va false positive larni ko'rib chiqing.",
            "Faqat tasdiqlangan biznes yo'llarini whitelist qiling.",
            "CRS qoidalarini yangilab turing; WAF ni butunlay o'chirmang.",
        ],
    ),
    "oom": (
        "Xotira tugagan",
        "Jarayon yoki tizimda bo'sh xotira qolmagan.",
        "RAM/cgroup limiti to'lgan; xotira oqishi, trafik o'sishi yoki kichik server bo'lishi mumkin.",
        "Worker crash, 502/504 xatolari, to'liq sayt to'xtashi xavfi.",
        [
            "free -h, dmesg OOM killer va cgroup memory limitlarini tekshiring.",
            "Avval oqishni toping, keyin PHP-FPM/nginx xotira limitini oshiring.",
            "Xotira monitoring va ogohlantirish qo'shing.",
        ],
    ),
    "disk_full": (
        "Disk to'lgan",
        "Fayl tizimida yozish uchun bo'sh joy yo'q (log, temp, sessiya, upload).",
        "Disk log, backup, upload yoki vaqtinchalik fayllar bilan to'lgan.",
        "Log/sessiya/upload yozilmaydi; ilova va logging ishlamaydi.",
        [
            "df -h va du -sh /*; eski log va temp fayllarni tozalang.",
            "Log rotatsiya/siqish; haqiqiy yuk bo'lsa diskni kengaytiring.",
        ],
    ),
    "too_many_files": (
        "Resurs tugashi",
        "Jarayon ochiq fayl deskriptorlari limitiga urilgan (ulimit -n).",
        "Juda ko'p parallel ulanish; past nofile limiti yoki FD oqishi.",
        "Yangi ulanishlar muvaffaqiyatsiz; yuk ostida vaqti-vaqti bilan 5xx.",
        [
            "worker_rlimit_nofile va tizim nofile limitlarini oshiring.",
            "Ulanish qayta ishlatish va upstream keepalive ni tekshiring.",
        ],
    ),
    "worker_crash": (
        "Worker jarayon crash",
        "Nginx worker jarayoni noodatiy tugadi.",
        "Modul xatosi, uchinchi tomon moduli, OOM kill yoki buzilgan holat.",
        "Qisqa ulanish uzilishlari; takrorlansa xizmat beqarorlashadi.",
        [
            "dmesg/journal da OOM yoki segfault izlang.",
            "So'nggi config/modul o'zgarishlarini tekshiring; kerak bo'lsa uchinchi tomon modulsiz sinang.",
            "nginx/openssl yangilanganligiga ishonch hosil qiling.",
        ],
    ),
    "php_fatal": (
        "PHP Fatal xato",
        "PHP fatal yoki ushlanmagan xato so'rov bajarilishini to'xtatgan.",
        "Ilova xatosi, yo'qolgan paket, memory_limit yoki max_execution_time.",
        "Tegishli endpointlar 500 qaytaradi; foydalanuvchi funksiyalari buziladi.",
        [
            "Logdagi fayl:qatorni ochib asosiy xatoni tuzating.",
            "Xotira oqishini inkor etgachgina memory_limit ni oshiring.",
            "PHP-FPM xato chastotasiga monitoring qo'shing.",
        ],
    ),
    "php_parse": (
        "PHP Parse xato",
        "PHP skriptni sintaksis xatosi tufayli tahlil qila olmadi.",
        "Noto'g'ri deploy, yarim yozilgan fayl yoki PHP versiya nomuvofiqligi.",
        "Butun skript ishlamaydi; shu faylga barcha so'rovlar 500.",
        [
            "Ko'rsatilgan fayl:qatordagi sintaksisni tuzating.",
            "Deploy atomik bo'lsin; PHP versiyasi kod bazasiga mos kelishi kerak.",
        ],
    ),
    "php_deprecated": (
        "PHP Deprecated",
        "Kod joriy PHP versiyasida eskirgan imkoniyatdan foydalanmoqda.",
        "Eski kod hali yangi PHP versiyasiga moslashtirilmagan.",
        "Hozir ishlashi mumkin, lekin keyingi PHP yangilanishida buziladi.",
        [
            "Keyingi PHP major yangilanishidan oldin tuzatish rejalashtiring.",
            "Vaqtinchalik o'chirish o'rniga chaqiruv joylarini tuzating.",
        ],
    ),
    "php_warning": (
        "PHP Warning",
        "PHP ogohlantirishi ba'zi kirishlarda ilova nuqsonini ko'rsatadi.",
        "Validatsiya yo'qligi, massiv kalit/o'zgaruvchi taxminlari yoki I/O xatolari.",
        "Ma'lumot sifati pasayishi yoki keyinchalik fatal bo'lishi mumkin; log shovqini.",
        [
            "Undefined key/variable larni to'g'ri validatsiya/default bilan tuzating.",
            "Ildiz sabab tuzatilgach log shovqinini kamaytiring.",
        ],
    ),
    "php_notice": (
        "PHP Notice",
        "PHP notice — fatal bo'lmagan kod muammosi (undefined index/offset/property).",
        "isset/?? tekshiruvlari yo'q yoki ixtiyoriy maydonlar ishlanmagan.",
        "Odatda darhol ko'rinmaydi; logni iflos qiladi va haqiqiy xatolarni yashiradi.",
        [
            "Null-safe kirish va input validatsiya qo'shing.",
            "Kod standarti / static analysis (PHPStan) ni kuchaytiring.",
        ],
    ),
    "php_fpm_timeout": (
        "PHP-FPM timeout",
        "Nginx PHP-FPM (FastCGI) javobini kutib timeout bo'ldi.",
        "Sekin PHP kodi, bloklangan I/O, kam pm children yoki timeout sozlamalari.",
        "Foydalanuvchilar 504 Gateway Timeout ko'radi; yuk ostida UX yomonlashadi.",
        [
            "Sekin endpointlarni profillang; DB so'rovlarini optimallashtiring.",
            "pm.max_children, request_terminate_timeout, fastcgi_read_timeout ni moslang.",
            "PHP-FPM status va slowlog ni tekshiring.",
        ],
    ),
    "php_fpm_crash": (
        "PHP-FPM crash",
        "PHP-FPM ulanishni kutilmaganda yopgan yoki connect ni rad etgan.",
        "FPM pool yuklangan, process crash (segfault), socket backlog to'la yoki noto'g'ri socket yo'li.",
        "PHP sahifalarida 502; vaqti-vaqti bilan sayt uzilishi.",
        [
            "php-fpm ishlayotganini va socket/path nginx bilan mosligini tekshiring.",
            "php-fpm error log va pool pm sozlamalarini ko'ring.",
            "Segfault va max_children tugashini tekshiring.",
        ],
    ),
    "upstream_timeout": (
        "Upstream timeout",
        "Nginx upstream serverga ulanish yoki o'qishda timeout bo'ldi.",
        "Backend sekin, yuklangan, tarmoq kechikishi yoki timeout juda qisqa.",
        "Proksi qilingan ilovalarda 502/504; yuk ostida zanjirli timeout.",
        [
            "Backend kechikishini o'lchang; masshtablang yoki optimallashtiring.",
            "proxy_connect/send/read_timeout ni SLA ga moslang.",
        ],
    ),
    "no_live_upstream": (
        "Upstream xato",
        "So'rov uchun sog'lom upstream backend qolmagan.",
        "Barcha backend o'chiq, health check o'tmagan yoki upstream bloki noto'g'ri.",
        "Virtual host / location bo'yicha to'liq uzilish.",
        [
            "Backend sog'ligini va nginx upstream holatini tekshiring.",
            "Upstream DNS/IP ni tuzating; quvvatni tiklang.",
        ],
    ),
    "upstream_connect": (
        "Upstream xato",
        "Nginx upstream bilan TCP ulanish o'rnata olmadi.",
        "Backend tinglamayapti, port noto'g'ri, firewall yoki jarayon o'chiq.",
        "Tegishli yo'llarda 502 Bad Gateway.",
        [
            "Upstream process sozlangan host:portda tinglayotganini tasdiqlang.",
            "Firewall/security group va SELinux ni tekshiring.",
        ],
    ),
    "upstream_reset": (
        "Reverse proxy xato",
        "Upstream nginx o'qishni tugatmasdan ulanishni yopgan.",
        "Backend crash, keep-alive nomuvofiqligi, so'rov hajmi limiti yoki ilova abort.",
        "Vaqti-vaqti bilan 502; foydalanuvchiga ko'rinadigan xatolar.",
        [
            "Xuddi shu vaqtdagi backend ilova loglari bilan solishtiring.",
            "Keep-alive va buffer sozlamalarini ko'rib chiqing (proxy_http_version 1.1).",
        ],
    ),
    "upstream_header": (
        "Reverse proxy xato",
        "Upstream javob sarlavhalarini o'qish yoki bufferlashda muammo.",
        "Juda katta cookie/header, kichik buffer yoki buzilgan javob.",
        "Ba'zi javoblarda 502; sessiya/cookie muammolari mumkin.",
        [
            "Katta header bo'lsa proxy_buffer_size / proxy_buffers ni oshiring.",
            "Ilovada Set-Cookie hajmini kamaytiring.",
        ],
    ),
    "ssl_handshake": (
        "SSL xato",
        "Mijoz va nginx (yoki nginx va upstream) o'rtasida TLS handshake muvaffaqiyatsiz.",
        "Protokol nomuvofiqligi, muddati o'tgan/noto'g'ri sertifikat, SNI yoki skaner shovqini.",
        "HTTPS mijozlar ulanmasligi mumkin; skanerlar ko'pincha shovqin beradi.",
        [
            "Sertifikat zanjiri va muddatini tekshiring (openssl s_client).",
            "ssl_protocols/ciphers ni mijoz talablariga moslang.",
            "Faqat skaner bo'lsa, hajm zararli bo'lmasa shovqin deb hisoblang.",
        ],
    ),
    "cert_verify": (
        "TLS xato",
        "Sertifikat tekshiruvi muvaffaqiyatsiz (ko'pincha nginx TLS client sifatida upstream ga).",
        "CA to'plami yo'q, self-signed upstream sertifikat yoki hostname nomuvofiqligi.",
        "Upstream ga HTTPS reverse proxy ishlamaydi.",
        [
            "To'g'ri CA o'rnating yoki proxy_ssl_trusted_certificate sozlang.",
            "Upstream sertifikat SAN ni ishlatilayotgan hostname ga moslang.",
        ],
    ),
    "dns": (
        "DNS xato",
        "Upstream yoki peer host nomi hal qilinmadi.",
        "DNS uzilishi, noto'g'ri resolver yoki hostname xatosi.",
        "Upstream ga yetib bo'lmaydi; nomli upstream larda 502.",
        [
            "resolver direktivasi va DNS serverlarini tekshiring.",
            "Hostdan dig/nslookup qiling; config dagi hostlarni tuzating.",
        ],
    ),
    "permission": (
        "Ruxsat xatosi",
        "Nginx worker OS ruxsati tufayli fayl/yo'lni ocha olmayapti.",
        "Noto'g'ri egasi/rejim, SELinux/AppArmor yoki ruxsat etilmagan yo'l.",
        "Statik fayl yoki config yuklanmaydi; 403/500 alomatlari.",
        [
            "Egasi (www-data/nginx) va katalog traverse bitlarini tekshiring.",
            "SELinux enforcing bo'lsa audit logni ko'ring.",
            "alias/root yo'llari to'g'riligiga ishonch hosil qiling.",
        ],
    ),
    "file_not_found": (
        "Fayl topilmadi",
        "Ko'rsatilgan fayl, skript yoki yo'l diskda yo'q.",
        "Deploy yetishmovchiligi, noto'g'ri root/alias yoki bot yo'q yo'llarni tekshirishi.",
        "Kontekstga qarab 404 yoki 502; botlar ko'pincha shovqin beradi.",
        [
            "Ilova deploy yo'llari nginx root/alias bilan mosligini tekshiring.",
            "Yo'l ma'lum skaner URI bo'lsa, xavfsizlik skaneri shovqini deb hisoblang.",
        ],
    ),
    "client_body": (
        "Konfiguratsiya xatosi",
        "Upload yoki so'rov tanasi client_max_body_size dan oshgan.",
        "Limit qonuniy upload uchun past yoki juda katta body bilan suiiste'mol urinishi.",
        "Katta yuklashlar 413 bilan muvaffaqiyatsiz.",
        [
            "Faqat kerakli location larda client_max_body_size ni oshiring.",
            "PHP post_max_size / upload_max_filesize ni moslang.",
        ],
    ),
    "broken_pipe": (
        "Tarmoq xatosi",
        "Nginx yozayotganda mijoz yoki peer ulanishni yopgan.",
        "Foydalanuvchi so'rovni bekor qilgan, LB timeout yoki beqaror tarmoq.",
        "Odatda past ta'sir; yuqori hajm timeout nomuvofiqligini ko'rsatishi mumkin.",
        [
            "LB idle timeout ni nginx/ilova bilan moslang.",
            "Yakka-yakka qisqa muddatli mijoz holatlarini e'tiborsiz qoldirish mumkin.",
        ],
    ),
    "config_error": (
        "Konfiguratsiya xatosi",
        "Nginx konfiguratsiyasi yaroqsiz yoki yuklanmadi.",
        "Sintaksis xatosi, yomon direktiva yoki include qilingan fayl yo'q.",
        "Reload/restart muvaffaqiyatsiz; sayt eski config da qolishi yoki o'chishi mumkin.",
        [
            "nginx -t ishga tushiring va ko'rsatilgan qatorlarni tuzating.",
            "include, map/geo fayllarini tekshiring.",
        ],
    ),
    "bot_activity": (
        "Bot faolligi",
        "Avtomatik mijoz rate limit yoki taqiqlangan joyga urilgan.",
        "Bot, skraper yoki limit_req/limit_conn ni oshirib yuboradigan mijozlar.",
        "Odatda shovqin; agar haqiqiy foydalanuvchi bo'lsa limit juda qattiq bo'lishi mumkin.",
        [
            "Mijozlar bot yoki haqiqiy foydalanuvchi ekanini aniqlang.",
            "limit_req zonalarni sozlang; kerak bo'lsa suiiste'mol IP larni firewall da bloklang.",
        ],
    ),
    "network_refused": (
        "Tarmoq xatosi",
        "Peer TCP ulanishni rad etgan (connection refused).",
        "Maqsad xizmat tinglamayapti yoki firewall yopgan.",
        "Bog'liq funksiya ishlamaydi (proxy, mail, auth va hokazo).",
        [
            "Xizmat holati va listen manzilini tekshiring.",
            "Mahalliy firewall qoidalarini ko'ring.",
        ],
    ),
    "security_scan_path": (
        "Xavfsizlik skaneri",
        "Avtomatik internet skaneri keng tarqalgan zaif yo'llarni tekshirmoqda "
        "(CMS admin, .env, phpMyAdmin, webshell, IoT exploit va hokazo).",
        "Internet fondagi shovqin — o'zi muvaffaqiyatli buzilish isboti emas.",
        "Log shovqini va ozgina resurs sarfi. Server nosozligi emas. "
        "Haqiqiy buzilish uchun qo'shimcha dalil kerak (kutilmagan yozuv, webshell, auth bypass).",
        [
            "WAF/ModSecurity yoqilgan holda qolsin.",
            "Admin panellarni MFA/VPN siz ochiq qoldirmang.",
            "Ixtiyoriy ravishda ma'lum skaner IP larni CDN/firewall da tashlang.",
            "Sof probe trafikni avariya deb baholamang.",
        ],
    ),
    "unknown": (
        "Noma'lum",
        "Log qatori ma'lum imzoga tushmadi.",
        "Notanish ilova, modul yoki kam uchraydigan xato matni.",
        "Qo'lda ko'rib chiqilmaguncha noma'lum; yangi muammolarni yashirishi mumkin.",
        [
            "Namuna qatorlarni qo'lda ko'rib chiqing.",
            "Takrorlanuvchi yangi sinf paydo bo'lsa analyzer patternlarini kengaytiring.",
        ],
    ),
    "unknown_high": (
        "Noma'lum",
        "Log qatori ma'lum imzoga tushmadi; nginx darajasi yuqori (crit/alert/emerg).",
        "Notanish ilova, modul yoki kam uchraydigan jiddiy xato matni.",
        "Qo'lda ko'rib chiqish kerak; yashirin infratuzilma muammosi bo'lishi mumkin.",
        [
            "Namuna qatorlarni zudlik bilan qo'lda tahlil qiling.",
            "Takrorlansa yangi pattern qo'shing.",
        ],
    ),
}

_UZ_BY_CATEGORY_EN: dict[str, str] = {
    "ModSecurity Block": "ModSecurity bloki",
    "Memory Exhausted": "Xotira tugagan",
    "Disk Full": "Disk to'lgan",
    "Resource Exhaustion": "Resurs tugashi",
    "Worker Process Crash": "Worker jarayon crash",
    "PHP Fatal Error": "PHP Fatal xato",
    "PHP Parse Error": "PHP Parse xato",
    "PHP Deprecated": "PHP Deprecated",
    "PHP Warning": "PHP Warning",
    "PHP Notice": "PHP Notice",
    "PHP-FPM Timeout": "PHP-FPM timeout",
    "PHP-FPM Crash": "PHP-FPM crash",
    "Upstream Timeout": "Upstream timeout",
    "Upstream Error": "Upstream xato",
    "Reverse Proxy Error": "Reverse proxy xato",
    "SSL Error": "SSL xato",
    "TLS Error": "TLS xato",
    "DNS Error": "DNS xato",
    "Permission Error": "Ruxsat xatosi",
    "File Not Found": "Fayl topilmadi",
    "Configuration Error": "Konfiguratsiya xatosi",
    "Network Error": "Tarmoq xatosi",
    "Bot Activity": "Bot faolligi",
    "Security Scan": "Xavfsizlik skaneri",
    "Unknown": "Noma'lum",
}


def localize_profile(rule_id: str, profile: CategoryProfile) -> CategoryProfile:
    """Return a new profile with Uzbek narrative fields."""
    pack = _UZ_BY_RULE.get(rule_id)
    if pack:
        cat_u, desc_u, root_u, impact_u, recs_u = pack
        return CategoryProfile(
            category=cat_u,
            severity=profile.severity,
            description=desc_u,
            root_cause=root_u,
            impact=impact_u,
            recommendations=list(recs_u),
            confidence=profile.confidence,
            is_security_scan=profile.is_security_scan,
            is_blocked_attack=profile.is_blocked_attack,
            is_application_bug=profile.is_application_bug,
            is_infrastructure=profile.is_infrastructure,
            is_config=profile.is_config,
        )

    cat_uz = _UZ_BY_CATEGORY_EN.get(profile.category, profile.category)
    return CategoryProfile(
        category=cat_uz,
        severity=profile.severity,
        description=profile.description,
        root_cause=profile.root_cause,
        impact=profile.impact,
        recommendations=list(profile.recommendations),
        confidence=profile.confidence,
        is_security_scan=profile.is_security_scan,
        is_blocked_attack=profile.is_blocked_attack,
        is_application_bug=profile.is_application_bug,
        is_infrastructure=profile.is_infrastructure,
        is_config=profile.is_config,
    )
