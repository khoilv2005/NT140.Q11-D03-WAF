sqlite3 waf_final.db

sudo docker run --name waf-mysql \
    -e MYSQL_ROOT_PASSWORD=my-secret-pw \
    -e MYSQL_DATABASE=wafdb \
    -e MYSQL_USER=waf \
    -e MYSQL_PASSWORD=wafadmin \
    -v waf-mysql-data:/var/lib/mysql \
    -p 3306:3306 \
    -d mysql:latest

sudo docker exec -it waf-mysql mysql -u waf -p wafdb