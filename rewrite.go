package main

import (
    "strings"
    "regexp"
    "path"
    "fmt"
)

type Rule struct {
    Pattern string
    To      string
    *regexp.Regexp
}

type RewriteMap struct {
    rules []*Rule
}

var regfmt = regexp.MustCompile(`:[^/#?()\.\\]+`)

func NewRule(pattern, to string) (*Rule, error) {
    pattern = regfmt.ReplaceAllStringFunc(pattern, func(m string) string {
	return fmt.Sprintf(`(?P<%s>[^/#?]+)`, m[1:])
    })

    reg, err := regexp.Compile(pattern)
    if err != nil {
	return nil, err
    }

    return &Rule{
	pattern,
	to,
	reg,
    }, nil
}

func (r *Rule) Rewrite(from string) string {
    if !r.MatchString(from) {
	return from
    }
    to := path.Clean(r.Replace(from))
    return to
}

func (r *Rule) Replace(from string) string {
    if !hit("\\$|\\:", r.To) {
	return r.To
    }

    regFrom := regexp.MustCompile(r.Pattern)
    match := regFrom.FindStringSubmatchIndex(from)
    result := regFrom.ExpandString([]byte(""), r.To, from, match)
    str := string(result[:])

    if hit("\\:", str) {
	return r.replaceNamedParams(from, str)
    }

    return str
}

var urlreg = regexp.MustCompile(`:[^/#?()\.\\]+|\(\?P<[a-zA-Z0-9]+>.*\)`)

func (r *Rule) replaceNamedParams(from, to string) string {
    fromMatches := r.FindStringSubmatch(from)

    if len(fromMatches) > 0 {
	for i, name := range r.SubexpNames() {
	    if len(name) > 0 {
		to = strings.Replace(to, ":"+name, fromMatches[i], -1)
	    }
	}
    }

    return to
}

func NewRewriteMap(rules map[string]string) *RewriteMap {
    var h RewriteMap
    for key, val := range rules {
	r, e := NewRule(key, val)
	if e != nil {
	    log.Fatal(e)
	}

	h.rules = append(h.rules, r)
    }

    return &h
}

func (h *RewriteMap) Rewrite(in string) string {
    for _, r := range h.rules {
	out := r.Rewrite(in)
	if out != in {
	    return out
	}
    }
    return in
}

func hit(pattern, str string) bool {
    r, e := regexp.MatchString(pattern, str)
    if e != nil {
	return false
    }
    return r
}
