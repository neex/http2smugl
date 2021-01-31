package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"sync"
	"time"
)

func detectMultipleTargets(targets []string,
	connectTo string,
	threads int,
	timeout time.Duration,
	csv *CSVLogWriter,
	verbose bool) error {
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })

	queue := make(chan *DetectParams)
	randomized := make(chan *DetectParams)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		randomizeJobOrder(1000000, queue, randomized)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, t := range targets {
			getDetectJobs(t, queue)
		}
		close(queue)
	}()

	wg.Add(threads)

	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()

			for job := range randomized {
				distinguishable, err := Detect(job, connectTo, timeout, verbose)
				var verdict string
				if err != nil {
					verdict = err.Error()
				} else {
					verdict = distinguishable.String()
				}

				fmt.Printf("%s: %v\n", job, verdict)
				if csv != nil {
					_ = csv.Log(job, distinguishable)
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

func getDetectJobs(target string, queue chan<- *DetectParams) {
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
						queue <- &DetectParams{
							Target:           target,
							DetectMethod:     dm,
							SmugglingMethod:  sm,
							SmugglingVariant: v,
							PaddingMethod:    pm,
							RequestMethod:    rm,
						}
					}
				}
			}
		}
	}
}

func randomizeJobOrder(randSize int, in <-chan *DetectParams, out chan<- *DetectParams) {
	if randSize <= 0 {
		panic(errors.New("randomizeJobOrder: randSize <= 0"))
	}
	buf := make([]*DetectParams, randSize)
	for job := range in {
		idx := rand.Intn(randSize)
		old := buf[idx]
		buf[idx] = job
		if old != nil {
			out <- old
		}
	}
	for _, job := range buf {
		if job != nil {
			out <- job
		}
	}
	close(out)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
