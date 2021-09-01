package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func main() {
	var (
		// root options
		timeout     time.Duration
		connectAddr string
		// request subcommand options
		bodyFile, bodyStr string
		requestMethod     string
		noAutoHeaders     bool
		noUserAgent       bool
		autoContentLength bool
		bodyToSend        []byte
		bodyLines         int
		// detect subcommand options
		verbose     bool
		detectMethod string
		threads     int
		targetsFile string
		csvLog      string
		tryHTTP3    bool
	)

	requestCmd := &cobra.Command{
		Use:     "request url [header [header...]]",
		Short:   "make one request with custom headers",
		Example: "request https://example.com/ \"transfer-encoding : chunked\"",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if noAutoHeaders && requestMethod != "GET" {
				return fmt.Errorf("cannot combine --method and --no-auto-headers")
			}
			if bodyFile != "" {
				if bodyStr != "" {
					return errors.New("both --body and --body-str specified")
				}
				data, err := ioutil.ReadFile(bodyFile)
				if err != nil {
					return err
				}
				bodyToSend = data
			} else {
				bodyToSend = []byte(unquoteArg(bodyStr))
			}

			target, err := url.Parse(args[0])
			if err != nil {
				return err
			}
			var headers []Header
			for _, h := range args[1:] {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid header: %#v", h)
				}
				if parts[0] == "" && strings.ContainsRune(parts[1], ':') {
					parts = strings.SplitN(parts[1], ":", 2)
					parts[0] = ":" + parts[0]
				}
				headers = append(headers, Header{unquoteArg(parts[0]), unquoteArg(parts[1])})
			}

			doAndPrintRequest(&RequestParams{
				Target:           target,
				Method:           unquoteArg(requestMethod),
				ConnectAddr:      connectAddr,
				Headers:          headers,
				NoAutoHeaders:    noAutoHeaders,
				NoUserAgent:      noUserAgent,
				AddContentLength: autoContentLength,
				Body:             bodyToSend,
				Timeout:          timeout,
			}, bodyLines)
			return nil
		},
	}

	detectCmd := &cobra.Command{
		Use:   "detect [flags] [url [url...]]",
		Short: "detect if an url is vulnerable",
		RunE: func(cmd *cobra.Command, args []string) error {
			targets := args
			if targetsFile != "" {
				data, err := ioutil.ReadFile(targetsFile)
				if err != nil {
					return err
				}
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						targets = append(targets, line)
					}
				}
			}

			var csvWriter *CSVLogWriter
			if csvLog != "" {
				var err error
				csvWriter, err = NewCSVLogWriter(csvLog)
				if err != nil {
					return err
				}
				defer func() {
					_ = csvWriter.Close()
				}()
			}

			var targetURLs []string
			for i := range targets {
				if !strings.Contains(targets[i], "/") {
					targetURLs = append(targetURLs, fmt.Sprintf("https://%s/", targets[i]))
					if tryHTTP3 {
						targetURLs = append(targetURLs, fmt.Sprintf("https+h3://%s/", targets[i]))
					}
				} else {
					targetURLs = append(targetURLs, targets[i])
				}
			}
			var methods []string
			if strings.Contains(detectMethod, ","){
				methods = strings.Split(strings.ToUpper(detectMethod),",")
			}else{
				methods = append(methods, strings.ToUpper(detectMethod))
			}

			return detectMultipleTargets(targetURLs,
				connectAddr,
				threads,
				timeout,
				csvWriter,
				methods,
				verbose)
		},
	}

	var rootCmd = &cobra.Command{
		Use: "http2smugl",
	}

	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 10*time.Second, "timeout to all requests")
	rootCmd.PersistentFlags().StringVar(&connectAddr, "connect-to", "", "override target ip")
	requestCmd.Flags().StringVar(&requestMethod, "method", "GET", "request method")
	requestCmd.Flags().StringVar(&bodyStr, "body-str", "", "send this string to body (escape seqs like \\r \\n are supported)")
	requestCmd.Flags().StringVar(&bodyFile, "body-file", "", "read request body from this file")
	requestCmd.Flags().BoolVar(&noAutoHeaders, "no-auto-headers", false, "don't send pseudo-headers automatically")
	requestCmd.Flags().BoolVar(&noUserAgent, "no-user-agent", false, "don't send user-agent")
	requestCmd.Flags().BoolVar(&autoContentLength, "auto-content-length", false, "add \"content-length\" header with body size")
	requestCmd.Flags().IntVar(&bodyLines, "body-lines", 10, "how many body lines to print (-1 means no limit)")

	detectCmd.Flags().BoolVar(&verbose, "verbose", false, "be more verbose")
	detectCmd.Flags().StringVar(&detectMethod, "method", "GET,POST,OPTIONS", "detect method")
	detectCmd.Flags().IntVar(&threads, "threads", 100, "number of threads")
	detectCmd.Flags().StringVar(&targetsFile, "targets", "", "read targets list from this file")
	detectCmd.Flags().StringVar(&csvLog, "csv-log", "", "log results into csv file")
	detectCmd.Flags().BoolVar(&tryHTTP3, "try-http3", false, "try HTTP/3 too when no protocol specified in a target")

	rootCmd.AddCommand(requestCmd, detectCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func unquoteArg(s string) string {
	if decoded, err := strconv.Unquote(`"` + s + `"`); err == nil {
		return decoded
	}
	return s
}

func doAndPrintRequest(params *RequestParams, bodyLines int) {
	_, response, err := DoRequest(params)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	if response == nil {
		return
	}
	for _, h := range response.Headers {
		fmt.Printf("%s: %s\n", h.Name, h.Value)
	}
	fmt.Println()
	lines := bytes.Split(response.Body, []byte{'\n'})
	for i, l := range lines {
		if bodyLines < 0 || i < bodyLines {
			fmt.Println(string(l))
		} else {
			break
		}
	}
}
