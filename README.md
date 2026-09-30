# sharefile

CLI interaktif untuk berbagi file melalui server relay Go. File disimpan di server sementara dan hanya bisa diunduh dengan token rahasia.

## Jalankan

```bash
go build -o sharefile .
```

### Server di VPS

```bash
export SHAREFILE_ADMIN_TOKEN="buat-token-admin-yang-panjang"
./sharefile serve --listen :8080 --data /var/lib/sharefile --ttl 24h
```

Untuk pemakaian internet, pasang reverse proxy HTTPS (misalnya Caddy) di depan port 8080. Teman tidak perlu menjalankan server; mereka cukup menjalankan perintah `get` yang dicetak setelah upload.

### Upload dan download

```bash
./sharefile share --server https://files.example.com --file ./arsip.zip --admin-token "$SHAREFILE_ADMIN_TOKEN"
./sharefile get --server https://files.example.com --code ABC12345 --token TOKEN_DARI_PENGIRIM --out ./arsip.zip
```

Tanpa argumen, binary membuka menu interaktif. `serve` dapat dijalankan di komputer lokal untuk LAN/tunnel, tetapi untuk akses langsung dari internet gunakan VPS atau tunnel seperti Cloudflare Tunnel/Tailscale Funnel.

## Keamanan

- Token share hanya ditampilkan saat upload dan tidak dimasukkan ke URL download.
- Share otomatis kedaluwarsa sesuai `--ttl` dan file ikut dihapus.
- Default maksimum file adalah 2 GiB; ubah dengan `--max-size` dalam byte.
- Gunakan HTTPS. Endpoint upload sebaiknya memakai `--admin-token`/`SHAREFILE_ADMIN_TOKEN` agar server publik tidak menjadi tempat upload anonim.
- Ini MVP relay sederhana: belum memiliki akun pengguna, antivirus, rate limiting, atau resumable upload.
