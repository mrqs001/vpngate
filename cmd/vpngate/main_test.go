package main

import "testing"

func TestHelpAndVersionAreSuccessful(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"version"}, {"run", "--help"}} {
		if e := run(args); e != nil {
			t.Fatal(e)
		}
	}
}

func TestControlNameAndRateValidation(t *testing.T) {
	for _, args := range [][]string{{"status", "--name", "../another"}, {"limit", "--name", "default"}, {"limit", "--mbps", "-1"}, {"run", "unexpected"}} {
		if e := run(args); e == nil {
			t.Fatal("invalid command accepted")
		}
	}
}
