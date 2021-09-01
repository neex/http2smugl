package main

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

func detectMultipleTargets(targets []string,
	connectTo string,
	threads int,
	timeout time.Duration,
	csv *CSVLogWriter,
	methods []string,
	verbose bool) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })

	queue := make(chan *DetectParams, threads)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(queue)

		pushDetectJobs(targets, queue, methods)
	}()

	wg.Add(threads)

	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()

			for job := range queue {
				distinguishable, err := Detect(job, connectTo, timeout, verbose)
				var verdict string
				if err != nil {
					verdict = err.Error()
				} else {
					verdict = distinguishable.String()
				}
				if distinguishable != Indistinguishable {
					fmt.Printf("%s: %v\n", job, verdict)
				}
				if csv != nil {
					_ = csv.Log(job, distinguishable)
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

func pushDetectJobs(targets []string, queue chan<- *DetectParams, methods []string) {
	for _, dm := range DetectMethods {
		for _, sm := range SmugglingMethods {
			if !dm.AllowsSmugglingMethod(sm) {
				continue
			}
			for _, pm := range PaddingMethods {
				for _, rm := range methods {
					variants := sm.GetVariants()
					for _, v := range variants {
						for _, target := range targets {
							queue <- &DetectParams{
								Target:           target,
								DetectMethod:     dm,
								SmugglingMethod:  sm,
								SmugglingVariant: v,
								PaddingMethod:    pm,
								RequestMethod:    strings.TrimSpace(rm),
							}
						}
					}
				}
			}
		}
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
