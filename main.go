// Command ythider turns YouTube into a search bar. It runs as a local proxy
// for YouTube's hostnames, strips the recommendation surfaces, and asks a
// local model whether each search fits what the user said they come for.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
)

var listenAddrs = []string{"127.0.0.1:443", "[::1]:443"}

const usage = `ythider: YouTube as a search bar, gated by a local model.

  sudo ythider install [--cooloff 24h|never] [--model NAME]
  sudo ythider upgrade            replace the running daemon with this build
  sudo ythider status
  sudo ythider request-unlock     start the cool-off before the password can be revealed
  sudo ythider cancel-unlock      change your mind
  sudo ythider reveal             show the password once the cool-off has passed
  sudo ythider unlock             remove everything (asks for the password)
  sudo ythider relock             replace a revealed password with a new unknown one
  sudo ythider seal               give up the way out: new password, no copy kept
       ythider eval --policy FILE QUERIES.tsv   measure the classifier on labeled queries
       ythider serve --dev --state DIR --listen ADDR   run unprivileged for development
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"serve":          cmdServe,
		"install":        cmdInstall,
		"upgrade":        cmdUpgrade,
		"status":         cmdStatus,
		"request-unlock": cmdRequestUnlock,
		"cancel-unlock":  cmdCancelUnlock,
		"reveal":         cmdReveal,
		"unlock":         cmdUnlock,
		"relock":         cmdRelock,
		"seal":           cmdSeal,
		"eval":           cmdEval,
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		if errors.Is(err, os.ErrPermission) {
			err = fmt.Errorf("%w (run with sudo)", err)
		}
		fmt.Fprintln(os.Stderr, "ythider:", err)
		os.Exit(1)
	}
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	state := fs.String("state", defaultStateDir, "state directory")
	listen := fs.String("listen", strings.Join(listenAddrs, ","), "comma-separated listen addresses")
	dev := fs.Bool("dev", false, "development mode: create a throwaway CA, leave /etc/hosts alone")
	fs.Parse(args)

	st := &store{dir: *state}
	if *dev {
		if _, err := os.Stat(st.path("ca/root.pem")); err != nil {
			if err := createAuthority(st.path("ca")); err != nil {
				return err
			}
		}
	}
	ca, err := loadAuthority(st.path("ca"))
	if err != nil {
		return err
	}
	srv := newServer(st, newOllamaClassifier(st.config()), upstreamTransport(newResolver()))
	if !*dev {
		go guardHosts()
	}
	go srv.warm()
	log.Printf("youtube-hider serving on %s", *listen)
	return srv.listenAndServe(strings.Split(*listen, ","), ca)
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	cooloff := fs.String("cooloff", "24h", `wait between request-unlock and reveal, or "never" to keep no copy of the password`)
	model := fs.String("model", defaultModel, "Ollama model used to classify searches")
	ollama := fs.String("ollama", defaultOllama, "Ollama endpoint")
	fs.Parse(args)

	never := *cooloff == "never"
	var wait time.Duration
	if !never {
		var err error
		if wait, err = time.ParseDuration(*cooloff); err != nil || wait < 0 {
			return fmt.Errorf("--cooloff %q: want a duration like 24h, or never", *cooloff)
		}
	}
	st := &store{dir: defaultStateDir}
	cfg := config{Model: *model, Ollama: *ollama}
	if err := install(st, cfg, wait, never); err != nil {
		return err
	}
	fmt.Println("Installed and locked. The unlock password was generated and not shown.")
	if never {
		fmt.Println("No copy of the password was kept: it cannot be revealed.")
	} else {
		fmt.Printf("To get it: `sudo ythider request-unlock`, wait %s, then `sudo ythider reveal`.\n", wait)
	}
	if err := modelReady(cfg); err != nil {
		fmt.Printf("\nThe classifier is not ready, so every search is blocked until it is:\n  %v\n", err)
	}
	fmt.Println("\nQuit and reopen your browser, then open https://www.youtube.com to write what belongs.")
	return nil
}

// modelReady reports whether Ollama is reachable and has the model pulled.
func modelReady(cfg config) error {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(strings.TrimRight(cfg.Ollama, "/") + "/api/tags")
	if err != nil {
		return fmt.Errorf("Ollama is not answering at %s; start it", cfg.Ollama)
	}
	defer resp.Body.Close()
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return err
	}
	for _, m := range tags.Models {
		if m.Name == cfg.Model || m.Name == cfg.Model+":latest" {
			return nil
		}
	}
	return fmt.Errorf("model %q is not pulled; run `ollama pull %s`", cfg.Model, cfg.Model)
}

func loadLock() (*store, *lock, error) {
	st := &store{dir: defaultStateDir}
	if err := requireRoot(); err != nil {
		return nil, nil, err
	}
	lk, err := st.lock()
	if err != nil {
		return nil, nil, err
	}
	if lk == nil {
		return nil, nil, errors.New("not installed")
	}
	return st, lk, nil
}

func cmdUpgrade([]string) error {
	if err := upgrade(&store{dir: defaultStateDir}); err != nil {
		return err
	}
	fmt.Println("Upgraded and restarted. Reload any open YouTube tabs.")
	return nil
}

func cmdStatus([]string) error {
	st, lk, err := loadLock()
	if err != nil {
		return err
	}
	cfg := st.config()
	fmt.Println("installed: yes")
	if run("launchctl", "print", "system/"+daemonLabel) == nil {
		fmt.Println("daemon:    running")
	} else {
		fmt.Println("daemon:    not loaded")
	}
	if st.policy().empty() {
		fmt.Println("policy:    not written yet; open https://www.youtube.com")
	} else {
		fmt.Println("policy:    set")
	}
	if err := modelReady(cfg); err != nil {
		fmt.Printf("model:     %s: %v\n", cfg.Model, err)
	} else {
		fmt.Printf("model:     %s ready\n", cfg.Model)
	}
	switch left, err := lk.remaining(time.Now()); {
	case lk.Cooloff < 0:
		fmt.Println("unlock:    sealed; no copy of the password exists")
	case err != nil:
		fmt.Printf("unlock:    locked; cool-off is %s once requested\n", time.Duration(lk.Cooloff)*time.Second)
	case left > 0:
		fmt.Printf("unlock:    requested; password can be revealed in %s\n", left.Round(time.Minute))
	default:
		fmt.Println("unlock:    cool-off passed; `sudo ythider reveal` shows the password")
	}
	return nil
}

func cmdRequestUnlock([]string) error {
	st, lk, err := loadLock()
	if err != nil {
		return err
	}
	if lk.Cooloff < 0 {
		_, err := lk.remaining(time.Now())
		return err
	}
	if lk.RequestedAt == nil {
		now := time.Now()
		lk.RequestedAt = &now
		if err := st.write("lock.json", lk); err != nil {
			return err
		}
	}
	left, _ := lk.remaining(time.Now())
	fmt.Printf("Unlock requested. The password can be revealed in %s.\n", left.Round(time.Minute))
	return nil
}

func cmdCancelUnlock([]string) error {
	st, lk, err := loadLock()
	if err != nil {
		return err
	}
	lk.RequestedAt = nil
	if err := st.write("lock.json", lk); err != nil {
		return err
	}
	fmt.Println("Unlock request cancelled. Still locked.")
	return nil
}

func cmdReveal([]string) error {
	_, lk, err := loadLock()
	if err != nil {
		return err
	}
	left, err := lk.remaining(time.Now())
	if err != nil {
		return err
	}
	if left > 0 {
		return fmt.Errorf("not yet: %s left in the cool-off", left.Round(time.Minute))
	}
	fmt.Println(lk.Sealed)
	return nil
}

func askPassword(lk *lock) error {
	fmt.Fprint(os.Stderr, "Unlock password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if !lk.verify(string(pw)) {
		return errors.New("wrong password")
	}
	return nil
}

func cmdUnlock([]string) error {
	st, lk, err := loadLock()
	if err != nil {
		return err
	}
	if err := askPassword(lk); err != nil {
		return err
	}
	if err := uninstall(st); err != nil {
		return err
	}
	fmt.Println("Removed. Quit and reopen your browser to get ordinary YouTube back.")
	return nil
}

func cmdRelock([]string) error {
	st, lk, err := loadLock()
	if err != nil {
		return err
	}
	if err := askPassword(lk); err != nil {
		return err
	}
	next, err := newLock(newPassword(), time.Duration(lk.Cooloff)*time.Second, lk.Cooloff < 0)
	if err != nil {
		return err
	}
	if err := st.write("lock.json", next); err != nil {
		return err
	}
	fmt.Println("Locked again with a new password that was not shown.")
	return nil
}

// cmdSeal replaces the password with a new one and keeps no copy, so the
// lock can no longer be opened through this program. It only ever tightens,
// which is why it does not ask for the current password.
func cmdSeal([]string) error {
	st, _, err := loadLock()
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "Sealing cannot be undone: the password is replaced and no copy is kept.\nType seal to go ahead: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != "seal" {
		return errors.New("not sealed")
	}
	sealed, err := newLock(newPassword(), 0, true)
	if err != nil {
		return err
	}
	if err := st.write("lock.json", sealed); err != nil {
		return err
	}
	fmt.Println("Sealed. Adding to the policy and appeals still work; nothing can be removed.")
	return nil
}

// cmdEval measures the classifier against labeled lines. A search is
// "allow<TAB>query" or "block<TAB>query"; a video adds columns:
// "allow<TAB>title<TAB>channel<TAB>category" (category optional). It reports
// agreement and latency, which is the only honest way to pick a model or
// tune a policy.
func cmdEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	policyPath := fs.String("policy", "", `policy JSON file: {"allowed": "...", "blocked": "..."}`)
	model := fs.String("model", defaultModel, "Ollama model")
	ollama := fs.String("ollama", defaultOllama, "Ollama endpoint")
	fs.Parse(args)
	if fs.NArg() != 1 || *policyPath == "" {
		return errors.New("usage: ythider eval --policy FILE [--model NAME] QUERIES.tsv")
	}
	raw, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}
	var p policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%s: %w", *policyPath, err)
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer f.Close()

	cls := newOllamaClassifier(config{Model: *model, Ollama: *ollama})
	ctx := context.Background()
	if _, err := cls.classify(ctx, p, searchItem("warm up").subject()); err != nil {
		return err
	}
	var times []time.Duration
	var n, agree, wrongAllow, wrongBlock, appealable int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		if len(cols) < 2 || (cols[0] != "allow" && cols[0] != "block") {
			continue
		}
		label, query := cols[0], cols[1]
		it := searchItem(query)
		if len(cols) >= 3 {
			it = item{Kind: "video", Title: cols[1], Channel: cols[2]}
			if len(cols) >= 4 {
				it.Detail = cols[3]
			}
		}
		start := time.Now()
		v, err := cls.classify(ctx, p, it.subject())
		if err != nil {
			return err
		}
		times = append(times, time.Since(start))
		n++
		switch {
		case v.Allow == (label == "allow"):
			agree++
		case v.Allow:
			wrongAllow++
			fmt.Printf("let through, labeled block:  %-40s %d%% %s\n", query, v.Confidence, v.Reason)
		default:
			wrongBlock++
			if v.Confidence < appealBelow {
				appealable++
			}
			fmt.Printf("kept out, labeled allow:     %-40s %d%% %s\n", query, v.Confidence, v.Reason)
		}
	}
	if n == 0 {
		return errors.New("no labeled queries found")
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	fmt.Printf("\n%s: %d/%d agree (%.0f%%); %d wrongly let through, %d wrongly kept out (%d of those could be appealed)\n", *model, agree, n, 100*float64(agree)/float64(n), wrongAllow, wrongBlock, appealable)
	fmt.Printf("latency: median %s, p95 %s\n", times[n/2].Round(time.Millisecond), times[min(n-1, n*95/100)].Round(time.Millisecond))
	return nil
}
