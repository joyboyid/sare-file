package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxDefault = int64(2 << 30) // 2 GiB

type Share struct {
	Code      string    `json:"code"`
	Token     string    `json:"token"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Store struct {
	mu       sync.RWMutex
	Dir      string
	Manifest string
	Shares   map[string]Share
	MaxSize  int64
}

func main() {
	if len(os.Args) == 1 {
		interactive()
		return
	}
	switch os.Args[1] {
	case "serve":
		serveCmd(os.Args[2:])
	case "share":
		shareCmd(os.Args[2:])
	case "get":
		getCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Perintah tidak dikenal: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`sharefile - berbagi file melalui server relay

Perintah:
  sharefile                         Buka menu interaktif
  sharefile serve [opsi]            Jalankan server relay
  sharefile share [opsi]            Upload dan buat kode share
  sharefile get [opsi]              Download dengan kode share

Contoh server publik:
  SHAREFILE_ADMIN_TOKEN='rahasia-kuat' sharefile serve --listen :8080 --data ./data

Contoh client:
  sharefile share --server https://domainmu.example --file ./foto.zip --admin-token 'rahasia-kuat'
  sharefile get --server https://domainmu.example --code ABC12345 --token TOKEN --out ./foto.zip

Catatan: untuk internet, jalankan server di VPS/host publik dan gunakan HTTPS melalui reverse proxy
(Caddy/Nginx). Jangan meneruskan port HTTP biasa jika token share harus dirahasiakan.`)
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "alamat listen")
	data := fs.String("data", "./sharefile-data", "folder penyimpanan")
	admin := fs.String("admin-token", os.Getenv("SHAREFILE_ADMIN_TOKEN"), "token upload admin (disarankan untuk server publik)")
	ttl := fs.Duration("ttl", 24*time.Hour, "masa berlaku share baru")
	max := fs.Int64("max-size", maxDefault, "ukuran file maksimum dalam byte")
	fs.Parse(args)

	st, err := openStore(*data, *ttl, *max)
	if err != nil {
		log.Fatal(err)
	}
	go st.cleanupLoop(*ttl)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/api/v1/upload", st.uploadHandler(*admin, *ttl))
	mux.HandleFunc("/api/v1/download/", st.downloadHandler)
	mux.HandleFunc("/api/v1/info/", st.infoHandler)

	srv := &http.Server{Addr: *listen, Handler: logging(mux), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Printf("sharefile server listen di %s, data %s", *listen, *data)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	<-stop
	_ = srv.Close()
}

func openStore(dir string, _ time.Duration, max int64) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, Manifest: filepath.Join(dir, "manifest.json"), Shares: map[string]Share{}, MaxSize: max}
	b, err := os.ReadFile(s.Manifest)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.Shares); err != nil {
		return nil, fmt.Errorf("manifest rusak: %w", err)
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.Shares, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Manifest + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Manifest)
}

func (s *Store) cleanupLoop(ttl time.Duration) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		s.cleanup(ttl)
	}
}

func (s *Store) cleanup(_ time.Duration) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	dirty := false
	for code, sh := range s.Shares {
		if now.After(sh.ExpiresAt) {
			_ = os.Remove(filepath.Join(s.Dir, code+".bin"))
			delete(s.Shares, code)
			dirty = true
		}
	}
	if dirty {
		_ = s.saveLocked()
	}
}

func (s *Store) uploadHandler(admin string, ttl time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if admin != "" && !secureEqual(r.Header.Get("X-Admin-Token"), admin) {
			http.Error(w, "admin token salah", http.StatusUnauthorized)
			return
		}
		if r.ContentLength < 0 || r.ContentLength > s.MaxSize {
			http.Error(w, "ukuran file melebihi batas", http.StatusRequestEntityTooLarge)
			return
		}
		name, err := url.PathUnescape(r.Header.Get("X-File-Name"))
		if err != nil || name == "" {
			name = "shared-file"
		}
		name = filepath.Base(name)
		code, err := randomString(8)
		if err != nil {
			http.Error(w, "gagal membuat kode", 500)
			return
		}
		token, err := randomString(32)
		if err != nil {
			http.Error(w, "gagal membuat token", 500)
			return
		}
		tmp := filepath.Join(s.Dir, code+".uploading")
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			http.Error(w, "gagal membuat file", 500)
			return
		}
		written, copyErr := io.Copy(f, io.LimitReader(r.Body, s.MaxSize+1))
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil || written > s.MaxSize {
			_ = os.Remove(tmp)
			http.Error(w, "upload gagal atau terlalu besar", http.StatusRequestEntityTooLarge)
			return
		}
		final := filepath.Join(s.Dir, code+".bin")
		if err := os.Rename(tmp, final); err != nil {
			_ = os.Remove(tmp)
			http.Error(w, "gagal menyimpan file", 500)
			return
		}
		sh := Share{Code: code, Token: token, Filename: name, Size: written, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(ttl)}
		s.mu.Lock()
		s.Shares[code] = sh
		err = s.saveLocked()
		s.mu.Unlock()
		if err != nil {
			_ = os.Remove(final)
			http.Error(w, "gagal menyimpan metadata", 500)
			return
		}
		writeJSON(w, http.StatusCreated, sh)
	}
}

func (s *Store) lookup(r *http.Request) (Share, bool) {
	code := strings.TrimPrefix(r.URL.Path, "/api/v1/download/")
	if strings.HasPrefix(r.URL.Path, "/api/v1/info/") {
		code = strings.TrimPrefix(r.URL.Path, "/api/v1/info/")
	}
	s.mu.RLock()
	sh, ok := s.Shares[code]
	s.mu.RUnlock()
	return sh, ok && time.Now().Before(sh.ExpiresAt) && secureEqual(r.Header.Get("Authorization"), "Bearer "+sh.Token)
}

func (s *Store) downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	sh, ok := s.lookup(r)
	if !ok {
		http.Error(w, "kode atau token tidak valid", 404)
		return
	}
	f, err := os.Open(filepath.Join(s.Dir, sh.Code+".bin"))
	if err != nil {
		http.Error(w, "file tidak ditemukan", 404)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": sh.Filename}))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

func (s *Store) infoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	sh, ok := s.lookup(r)
	if !ok {
		http.Error(w, "kode atau token tidak valid", 404)
		return
	}
	sh.Token = ""
	writeJSON(w, 200, sh)
}

func shareCmd(args []string) {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	server := fs.String("server", "", "URL server")
	file := fs.String("file", "", "path file")
	admin := fs.String("admin-token", os.Getenv("SHAREFILE_ADMIN_TOKEN"), "token admin")
	fs.Parse(args)
	if *server == "" {
		*server = prompt("URL server: ")
	}
	if *file == "" {
		*file = prompt("File: ")
	}
	if err := upload(*server, *file, *admin); err != nil {
		log.Fatal(err)
	}
}

func upload(server, path, admin string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(server, "/")+"/api/v1/upload", f)
	if err != nil {
		return err
	}
	req.ContentLength = info.Size()
	req.Header.Set("X-File-Name", url.PathEscape(filepath.Base(path)))
	if admin != "" {
		req.Header.Set("X-Admin-Token", admin)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
		return fmt.Errorf("server: %s", strings.TrimSpace(string(b)))
	}
	var sh Share
	if err := json.NewDecoder(resp.Body).Decode(&sh); err != nil {
		return err
	}
	fmt.Printf("\nBerhasil dibagikan!\nKode : %s\nToken: %s\nBerlaku sampai: %s\n\nPerintah teman:\nsharefile get --server %s --code %s --token %s --out %s\n", sh.Code, sh.Token, sh.ExpiresAt.Local().Format(time.RFC3339), server, sh.Code, sh.Token, sh.Filename)
	return nil
}

func getCmd(args []string) {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	server := fs.String("server", "", "URL server")
	code := fs.String("code", "", "kode share")
	token := fs.String("token", "", "token share")
	out := fs.String("out", "", "file output")
	fs.Parse(args)
	if *server == "" {
		*server = prompt("URL server: ")
	}
	if *code == "" {
		*code = prompt("Kode: ")
	}
	if *token == "" {
		*token = prompt("Token: ")
	}
	if err := download(*server, *code, *token, *out); err != nil {
		log.Fatal(err)
	}
}

func download(server, code, token, out string) error {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(server, "/")+"/api/v1/download/"+url.PathEscape(code), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
		return fmt.Errorf("server: %s", strings.TrimSpace(string(b)))
	}
	if out == "" {
		out = code + "-download"
	}
	out = filepath.Clean(out)
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("Downloaded %d byte ke %s\n", n, out)
	return nil
}

func interactive() {
	fmt.Println("sharefile - berbagi file dari internet")
	for {
		fmt.Println("\n1) Jalankan server\n2) Upload/share file\n3) Download file\n4) Keluar")
		switch prompt("Pilih: ") {
		case "1":
			serveCmd(nil)
			return
		case "2":
			shareCmd(nil)
		case "3":
			getCmd(nil)
		case "4":
			return
		default:
			fmt.Println("Pilihan tidak valid")
		}
	}
}

func prompt(label string) string {
	fmt.Print(label)
	var v string
	fmt.Scanln(&v)
	return strings.TrimSpace(v)
}
func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")[:n], nil
}
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
