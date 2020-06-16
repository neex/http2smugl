package main

import (
	"fmt"
	"math/rand"
	"net/url"
	"sync"
	"time"
)

func detectMultipleTargets(targets []string, connectTo string, threads int, timeout time.Duration, verbose bool) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	var jobs []DetectParams
	for _, t := range targets {
		jobs = append(jobs, getDetectJobs(t)...)
	}

	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(jobs), func(i, j int) { jobs[i], jobs[j] = jobs[j], jobs[i] })

	queue := make(chan *DetectParams)
	var wg sync.WaitGroup
	wg.Add(threads)

	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()

			for job := range queue {
				distinguishable, err := Detect(job, connectTo, timeout, verbose)
				var verdict string
				switch {
				case err != nil:
					verdict = err.Error()
				case distinguishable:
					verdict = "distinguishable"
				case !distinguishable:
					verdict = "indistinguishable"
				}

				fmt.Printf("%s: %v\n", job, verdict)
			}
		}()
	}

	for i := range jobs {
		queue <- &jobs[i]
	}

	close(queue)
	wg.Wait()
	return nil
}

func getDetectJobs(target string) (params []DetectParams) {
	path := "/"
	if u, err := url.Parse(target); err == nil {
		path = u.Path
	}

	for _, dm := range DetectMethods {
		for _, sm := range SmugglingMethods {
			if !dm.AllowsSmugglingMethod(sm) {
				continue
			}
			variants := sm.GetVariants(path)
			for _, v := range variants {
				for _, pm := range PaddingMethods {
					for _, rm := range []string{"GET", "POST", "OPTIONS"} {
						params = append(params, DetectParams{
							Target:           target,
							DetectMethod:     dm,
							SmuggleMethod:    sm,
							SmugglingVariant: v,
							PaddingMethod:    pm,
							RequestMethod:    rm,
						})
					}
				}
			}
		}
	}
	return
}
