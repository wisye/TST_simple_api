## Simple API untuk memberikan "kunci cryptography"

> Untuk mengetes API bisa dengan menggunakan
```bash
curl -X POST "https://web-production-39f2.up.railway.app/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=furina&password=ilovefurinasomuchfrfr"
```
> untuk mendapatkan token autenthication, disini masih menggunakan local database dan token masih berupa username
```{"access_token":"furina","token_type":"bearer"}⏎ ```

> Setelah itu bisa melakukan request ke /api/key dengan token yang diberikan
```bash
curl -X GET "https://web-production-39f2.up.railway.app/api/key" \
      -H "Authorization: Bearer furina"
```
> untuk mendapatkan "kunci cryptography"
```{"key":"a09d5e81a8bcf8c8aa37b4c5a9952a88"}⏎ ```

> Jika melakukan request tanpa menggunakan token authentication
```bash
curl -X GET "https://web-production-39f2.up.railway.app/api/key"
```
> request akan ditolak
```{"detail":"Not authenticated"}⏎ ```
