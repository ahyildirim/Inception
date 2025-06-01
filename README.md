
## ADIM 1 - DOCKER KURULUMU
Öncelikle Docker apt repo'sunu kurmamız gerekiyor:
```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
```
Sonrasında `sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin` komutu ile gerekli her şeyi yüklüyoruz. En sonda test amaçlı `sudo docker run hello-world`çalıştırıyoruz.
## ADIM 2 - DOSYA YOLLARINI AYARLAMAK
Subjectte bizden istenen dosya yollarını oluşturuyoruz. 

    cd Desktop && mkdir -p inception/srcs/requirements
    touch inception/Makefile && touch inception/srcs/.env
    cd inception/srcs/requirements && mkdir -p nginx mariadb wordpress

## ADIM 3 - CONTAINERLARI OLUŞTURMAK
### .env
Öncelikle .env dosyasını dolduralım. Burada kullanabileceğimiz potansiyel environment variables şunlar olabilir:

```c
    DB_DATABASE=wordpress
    DB_HOST=mariadb:3306
    DB_USER_NAME=ahyildir
    DB_USERPASS=123
    DB_ROOTPASS=321
    WP_ADMIN_NAME=ahyildir
    WP_ADMINPASS=123
    WP_ADMIN_MAIL=ahyildir@student.42istanbul.com.tr
    WP_USER_NAME=ahmet
    WP_USERPASS=321
    WP_USER_MAIL=ahmet@hotmail.com
    WP_TITLE="Inception"
    DOMAIN=ahyildir.42.fr
```
### NGINX
Şimdi ise nginx için bir konfigürasyon dosyası oluşturalım. `cd inception/srcs/requirements/nginx && touch default.conf` komutunu yazıp içini dolduralım

```nginx
server {
	listen 443 ssl; #IPV4 üzerinden sadece 443 portunu dinletmek için. SSL sertifikası olduğunu belirtmek için ssl keywordü kullanılır.
	listen [::]:443 ssl; #IPV6 üzerinden sadece 443 portunu dinletmek için. SSL sertifikası olduğunu belirtmek için ssl keywordü kullanılır.

	server_name ahyildir.42.fr; #Bu domainden gelen istekleri karşılamak için.

	ssl_protocols TLSv1.2 TLSv1.3; #SADECE TSL1.2 ve TSL1.3 protokollerine izin vermek için. Böylece eski ve güvensiz sürümler engellenir
	ssl_certificate /etc/ssl/ahyildir.42.fr.crt; #openssl komutu ile oluşturduğumuz SSL sertifikasının dosya yolu
	ssl_certificate_key /etc/ssl/ahyildir.42.fr.key; #Aynı şekilde Sertifikaya ait özel anahtarın dosyası

	root /var/www/html/wordpress; #Web Sunucusunun kök dizini. (HTML, CSS vb. dosyalar burada olur. Wordpress dosyaları bu dizinde olmalı).
	index index.php index.html index.htm; #Dizine istek geldiğinde sırası ile hangi dosyaların ana sayfa olarak gösterileceğini belirtir.

	location / { #URL ile gelen istekte önce tam dosya adı aranır, sonra dizin aranır, eğer hiçbirisi yoksa 404 döndürülür.
		try_files $uri $uri/ =404;
	}

# FastCGI, NGINX'in PHP dosyalarını doğrudan çalıştırmak yerine,
# php-fpm gibi bir arka uç sunucuya iletmesini sağlayan bir protokoldür.
# Bu yapı sayesinde NGINX statik içerikleri sunarken,
# dinamik PHP içerikler ayrı bir servis (php-fpm) tarafından işlenir.

	location ~ \.php$ {
		include snippets/fastcgi-php.conf; #Gerekli FastCGI ayarlarını yükler
		fastcgi_pass wordpress:9000; #PHP dosyaları wordpress containerindaki php-fpm servisine gönderilir
	}

	location ~ /\.ht { #.htaccess, .htpasswd gibi özel şifreler barındıran dosyaların erişimini tamamen engeller.
		deny all;
	}
}
```
Ardından `touch Dockerfile` komutu ile Dockerfile oluşturalım ve içini dolduralım
```dockerfile
#RUN KOMUTU: Yeni bir layerda komut çalıştırılır ve komutun sonucu image'a yüklenir.
#Bu komut genelde gerekli uygulamaları paketleri yüklemek için kullanılır.
#Docker ilk kez başlatıldığında çalıştırılır, bir sonraki başlatımlarda çalışmaz.

#CMD KOMUTU: Docker her başlatıldığında bu komut çalışır.
#Birden fazla CMD eklerseniz YALNIZCA en sondaki CMD komutu çalışır.
#Docker başlatılırken herhangi bir argüman yollanırsa, bu CMD komutu yoksayılır.

#ENTRYPOINT KOMUTU: CMD ile benzer mantıkta çalışır.
#Fakat entrypoint komutu kullanıldığında entrypoint içindeki komut ana komut, cmd ise argüman olur.

#Docker içinde Debianın en son sürümünün slim(sadece gerekli paketlerinin yüklü olduğu versiyon) kullanılacağını belirtir.
FROM debian:bookworm-slim

#DUMB-INIT NEDİR?
#bir "init process" (PID 1) gibi davranan küçük bir programdır.    
#Container içindeki uygulamanın başlatılması ve düzgün sonlandırılmasını sağlar.
#Sinyalleri (CTRL+C gibi) doğru şekilde iletir, zombi işlemleri engeller.
#Özellikle NGINX gibi "daemon" olmayan servisleri düzgün başlatmak için kullanılır.

#Docker içinde bize gerekecek dumb-init, openssl ve nginx'i yükler
RUN apt-get update -y \
	&& apt-get upgrade -y \
	&& apt-get install -y dumb-init openssl nginx \
	&& apt-get clean -y

#Sertifikamızı docker içinde kurulumunu yapar.
#req: Sertifika isteği oluşturur.
#-x509: X.509 formatında doğrudan sertifika üretir.
#-nodes: Anahtar dosyası şifrelenmesin (NGINX kullanabilsin).
#-days 365: Sertifika 365 gün geçerli olsun.
#-newkey rsa:4096: 2048-bit RSA anahtarı oluştur.
#-keyout: Özel anahtarın kaydedileceği yol.
#-out: Sertifikanın kaydedileceği yol.
#-subj C(ÜLKE), ST(ŞEHİR), L(İLÇE), O(KURUM ADI), OU(DEPARTMAN), CN(DOMAIN ADI)
#-subj sayesinde form açılmadan direkt olarak komut satırında sertifika bilgilerini vermemizi sağlar
#Bu sayede openssl yukarıda girdiğimiz soruları sormaz.
RUN openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
	-subj "/C=TR/ST=KOCAELI/L=GEBZE/O=42Kocaeli/OU=Student/CN=ahyildir.42.fr" \
	-keyout /etc/ssl/ahyildir.42.fr.key -out /etc/ssl/ahyildir.42.fr.crt

#Bu komutla localdeki biraz önce oluşturduğumuz .conf dosyasını docker ortamında
#ngnix'in konfigürasyonunun olduğu yere kopyalar.
COPY conf/default.conf /etc/nginx/sites-enabled/default

EXPOSE 443 #Bu komutla bu container'ın dış dünyaya 443(HTTPS) portundan açılacağını bildirir

#Docker container'ı ekstra güvenlik için (memory leak, zombi process) gibi istenmeyen
#ve container'ı bozabilecek durumlardan korumak için öncelikle sahte process oluşturur.
#Bu process sayesinde kapatma sinyalleri doğru bir şekilde yakalanır.
#Ardından CMD komutu ile nginx başlatılır ve daemon off komutu ile nginx foreground'da çalışır
#Bu sayede nginx kapandığı zaman container doğru ve düzgün bir şekilde kapanır.
#aslında şu çalışmış olur: "/usr/bin/dumb-init -- nginx -g daemon off;"
ENTRYPOINT [ "/usr/bin/dumb-init", "--" ]
CMD ["nginx", "-g", "daemon off;"]
```
### MARIADB
Şimdi oluşturduğumuz mariadb klasörünün içine girip bir adet conf klasörü, bir adet tools klasörü ve bir de Dockerfile dosyası oluşturalım. conf klasörünün içine girip mariadb.cnf adlı bir dosya oluşturup için dolduralım

```c
[mysqld]
#Wordpress Container'ının erişebilmesi için. 
#Normalde MariaDB sadece 127.0.0.1(localhost) dinler, bu durumda başka bir container erişemez.
bind-address=0.0.0.0 
#Wordpress için kullanılması zorunlu olmasa da kullanılması tavsiye edilen, charset tipi. 
#Bu tip emojiler dahil her şeyi destekler.
character-set-server=utf8mb4 
collation-server=utf8mb4_general_ci
```
Sonra tools dosyası içine girip bir adet sql_start.sh isimli bir dosya oluşturalım ve içini dolduralım

```bash
#!/bin/bash

#Scriptte herhangi bir hata durumunda anında çıkış yapar.
set  -e

init_mariadb(){
	#MariaDB sunucusunu ek güvenlikler ile ARKA PLANDA(daemon) olarak başlatır.
	#--datadir, veritabanı dosyalarının nerede kaydedileceğini belirtir
	mysqld_safe  --datadir="/var/lib/mysql" &

	#MariaDB'ye 60 saniye boyunca ping atar ve hazır olmasını bekler, hazırsa mesajı basar.
	#Hazır değilse hazır olması bekleniyor mesajı basasr.
	for  i  in {1..30}; do
		if  mysqladmin  ping  --silent; then
			echo  "MariaDB is up!"
			break
		fi

		echo  "Waiting for MariaDB to be ready... ($i)"
		sleep  2
	done

	#Root şifresi olmadan bağlanmayı dener, eğer bağlantı başarılı olursa root şifresini ayarlar.
	#2>/dev/null satırı hata mesajlarını gizler.
	if  mysql  -u  root  -e  "SELECT 1;"  2>/dev/null; then
		echo  "Root password not set, setting now..."
		mysql  -u  root  <<	EOF
		ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOTPASS}';
		FLUSH PRIVILEGES;
	EOF
	else
		echo  "Root password already set or cannot connect without password."
	fi

	# Şifre ayarlandıktan sonra root şifresi ile bağlanmayı dener, bağlanamazsa hata mesajı basıp çıkar.
	if  !  mysql  -u  root  -p"${DB_ROOTPASS}"  -e  "SELECT 1;"; then
		echo  "ERROR: Cannot connect to MariaDB with root password. Exiting."  >&2
		exit  1
	fi 

	#Database'i ve kullanıcıyı oluşturur. Kullanıcıya oluşturduğu database'in tüm yetkilerini verir.
	echo  "Creating database and user if not exists..."
	mysql  -u  root  -p"${DB_ROOTPASS}"  <<EOF
	CREATE DATABASE IF NOT EXISTS \`${DB_DATABASE}\`;
	CREATE USER IF NOT EXISTS '${DB_USER_NAME}'@'%' IDENTIFIED BY '${DB_USERPASS}';
	GRANT ALL PRIVILEGES ON \`${DB_DATABASE}\`.* TO '${DB_USER_NAME}'@'%';
	FLUSH PRIVILEGES;
EOF
}

echo  "Starting MariaDB initialization..." 
init_mariadb 

#Container'ın kapanmaması için mysql processini exec ile foregrounda alıyoruz.
echo  "Switching to MariaDB foreground process..." 
exec mysqld_safe --datadir="/var/lib/mysql"
```

Son olarak Dockerfile'ı dolduralım
```dockerfile
FROM debian:bookworm-slim #Son sürüm debian, slim versiyondan.

#Gerekli mariadb servisini kur
RUN apt-get update -y && apt-get install -y \
		mariadb-server \
		&& apt-get clean

# MariaDB dizinlerini oluştur ve izinleri ayarla
RUN mkdir -p /var/run/mysqld \
		&& chown -R mysql:mysql /var/run/mysqld \
		&& chown -R mysql:mysql /var/lib/mysql

#Konfigürasyon dosyasını MariaDB konfigürasyon dosya yoluna kopyala
COPY conf/mariadb.cnf /etc/mysql/mariadb.conf.d/50-server.cnf

#Scripti bir klasöre kopyala ardından çalıştırma izini ver
COPY tools/sql_start.sh /tmp/
RUN chmod +x /tmp/sql_start.sh

#MariaDB portunu 3306'dan aç.
EXPOSE 3306

#Scripti dumb-init ile foregroundda çalıştır.
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/bin/bash", "/tmp/sql_start.sh"]
```
### WORDPRESS

Öncelikle conf klasörü oluşturup ardından www.conf adlı bir dosya oluşturup konfigürasyon dosyası oluşturalım ve içini dolduralım

```c
[www]

//PHP süreçlerinin hangi kullanıcı ve grup içinde çalışacağı belirtilir.
//Wordpress'in kullanıcısı ve grubu www-data'dır
user = www-data
group = www-data

//Hangi adres ve porttan dinleneceğini belirtir. Subjectte 9000 portu istendiği için 9000
//Normalde localhost'u dinleyen PHP bu sayede doğru adresi dinler ve dışarıya bağlanabilir
listen = wordpress:9000
```

Sonrrasında tools klasörü oluşturup içinde wp_setup.sh adlı bir bash script dosyası oluşturup içini dolduralım.

```bash
#!/bin/bash

#Eğer Wordpress kurulu değil ise
if  !  wp  core  is-installed  --path=/var/www/html/wordpress  --allow-root; then
	echo  "🚀 WordPress indiriliyor..."
	#Wordpress'in çekirdek dosyalarını var/www/html/wordpress yoluna indirir
	#allow-root ile komutları root kullanıcısı ile çalıştırır.
	wp  core  download  --path=/var/www/html/wordpress  --allow-root

	echo  "🔧 wp-config.php oluşturuluyor..."
	# WordPress'in wp-config.php yapılandırma dosyasını oluştur.
	# --path → wp-config.php dosyasının nereye oluşturulacağını belirtir.
	# --allow-root → root olarak çalıştırmaya izin ver.
	# --dbname → WordPress'in bağlanacağı veritabanının adı.
	# --dbhost → Veritabanı sunucusunun host adı (genelde docker-compose servis ismi, örneğin: mariadb).
	# --dbprefix → Veritabanı tabloları için eklenecek önek. wp_ varsayılanıdır.
	# --dbuser → Veritabanı bağlantısı için kullanılacak kullanıcı adı.
	# --dbpass → Yukarıdaki kullanıcının şifresi.
	wp  config  create  --path=/var/www/html/wordpress  --allow-root  \
		--dbname=$DB_DATABASE  \
		--dbhost=$DB_HOST  \
		--dbprefix=wp_  \
		--dbuser=$DB_USER_NAME  \
		--dbpass=$DB_USERPASS

	# WordPress çekirdeğini kurar (veritabanına tabloları ekler ve siteyi yapılandırır).
	# --url → WordPress’in kurulacağı alan adı (örneğin: https://ahyildir.42.fr).
	# --title → Site başlığı (örneğin: Ahmet'in Blogu).
	# --admin_user → Admin hesabı kullanıcı adı.
	# --admin_password → Admin hesabı şifresi.
	# --admin_email → Admin hesabına ait e-posta adresi.
	wp  core  install  --path=/var/www/html/wordpress  --allow-root  \
		--url=$DOMAIN  \
		--title="$WP_TITLE"  \
		--admin_user=$WP_ADMIN_NAME  \
		--admin_password=$WP_ADMINPASS  \
		--admin_email=$WP_ADMIN_MAIL

	# Mevcut tüm WordPress eklentilerini günceller.
	wp  plugin  update  --path=/var/www/html/wordpress  --allow-root  --all

	# Yeni bir kullanıcı oluşturur (genellikle normal kullanıcı).
	# $WP_USER_NAME → Oluşturulacak kullanıcının adı.
	# $WP_USER_MAIL → Kullanıcının e-posta adresi.
	# --user_pass → Kullanıcının şifresi.
	wp  user  create  --path=/var/www/html/wordpress  --allow-root  \
		$WP_USER_NAME  $WP_USER_MAIL  \
		--user_pass=$WP_USERPASS
	
	# WordPress'in medya dosyalarının yüklendiği uploads klasörünün sahipliğini değiştir.
	# -R → recursive (alt dizinlerle birlikte uygula).
	# www-data kullanıcısı, web sunucusunun çalıştığı kullanıcıdır.
	# PHP-FPM'nin PID dosyasını yazacağı dizini oluşturur.
	chown  www-data:www-data  /var/www/html/wordpress/wp-content/uploads  --recursive
	mkdir  -p  /run/php/

# Otomatik WordPress kurulumu (wp-cli yoksa elle yapılmalı)
	echo  "✅ WordPress yapılandırması tamamlandı."
else
	echo  "📂 WordPress zaten kurulmuş."
fi

# PHP-FPM servisini başlatır.
# -F → "Foreground" modunda çalıştırır. Yani arka planda daemon olarak çalışmaz.
# Container kapanmaması için PHP-FPM servisini foregroundda çalıştırır.
php-fpm8.2  -F
```

Ardından bir adet Dockerfile oluşturalım ve içini dolduralım

```dockerfile
FROM debian:bookworm-slim

RUN apt-get update -y && apt-get install -y \
	dumb-init curl php-fpm php-mysql php-mysqli mariadb-client && \
	apt-get clean -y

#WordPress’i komut satırından kurmak ve yapılandırmak için wp-cli aracını indirir
#wp-cli: WordPress sitelerini komut satırından yönetmek için kullanılan bir araçtır.
#Ardından çalıştırabilmek için execute iznini verir
RUN curl -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && \
	chmod +x /usr/local/bin/wp

#Wordpress dosyasını oluşturur
RUN mkdir -p /var/www/html/wordpress

#Script ve konfigürasyon dosyalarını kopyalar
COPY ./tools/wp_setup.sh /tmp/
COPY ./conf/www.conf /etc/php/8.2/fpm/pool.d/www.conf

#Container'ın 9000 portunu dinlemesini sağlar
EXPOSE 9000

ENTRYPOINT [ "/usr/bin/dumb-init", "--" ]
CMD ["/bin/bash", "/tmp/setup.sh"]
```

Şimdi ise docker-compose.yml dosyamızı oluşturalım. Docker-compose tüm dockerfile'ları tek tek başlatmamıza gerek olmadan, veya bağlantı kurmak için oluşturacağımız networkü el ile kurmamıza gerek kalmadan, volumeları el ile kurmamıza gerek kalmadan kurabildiğimiz kompakt bir docker aracıdır.

```yml
#Docker versiyonu
version: "3.9"

#Sırarı ile hangi servislerin başlatılacağı
#İlk olarak mariadb başlatılır, çünkü wordpress mariadb'ye, nginx ise wordpress'e bağlantılıdır.
#build -> hangi dockerfile kullanılacağı, 
#image -> build sonrası image hangi isimde olacak
#container_name -> Container adı
#restart -> Container crashlenirse her zaman(sürekli) yeniden başlatmayı dene
#env_file -> hangi env dosyasının kullanılacağı.
#networks -> Container'ın hangi network üzerinde olacağı.
#volumes -> Container silinse bile verilerini saklamak için oluşturulan yerler
#ports -> Container'ın dış dünyaya hangi port ile açılacağını belirtir.
services:
	mariadb:
		build:
			context: ./requirements/mariadb
		image: mariadb:beta
		container_name: mariadb
		restart: always
		env_file:
			- .env
		networks:
			- inception
		volumes:
			- mariadb:/var/lib/mysql

	wordpress:
		build:
			context: ./requirements/wordpress
		image: wordpress:beta
		container_name: wordpress
		restart: always
		depends_on:
			- mariadb
		env_file:
			- .env
		networks:
			- inception
		volumes:
			- wordpress:/var/www/html/wordpress

	nginx:
		build:
			context: ./requirements/nginx
		image: nginx:beta
		container_name: nginx
		restart: always
		depends_on:
			- wordpress
		env_file:
			- .env
		networks:
			- inception
		volumes:
			- wordpress:/var/www/html/wordpress
		ports:
			- 443:443

#Containerların birbirleri ile iletişim kuracağı inception ağını oluşturur.
#bridge tipinde bir bağlantı sağlar, bu bağlantı docker'ın default bağlantı tipidir
#Bu bağlantı tipi sayesinde dockerlar birbirlerinden izole fakat birbirleri ile iletişimde çalışır.
networks:
	inception:
		driver: bridge
		name: inception

#Containerlar için gerekli volumeları oluşturur
#Volumelar containerlar silinse dahi verileri saklamak için kullanılır.
#local driverda, wordpress isminde, bilgisayarda belirtilen yolda mount edilir(bağlanır).
volumes:
	wordpress:
		driver: local
		name: wordpress
		driver_opts:
			type: none
			o: bind
			device: /home/ahyildir/data/wordpress

	mariadb:
		driver: local
		name: mariadb
		driver_opts:
			type: none
			o: bind
			device: /home/ahyildir/data/mariadb
```
