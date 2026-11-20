/*
    Copyright NetFoundry Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

package config

import (
	"fmt"
	"net/url"
)

// CheckControllerURL reports why u is not an acceptable controller API URL:
// it must be https with a host, and carry no user info, query or fragment.
func CheckControllerURL(u *url.URL) error {
	switch {
	case u == nil:
		return fmt.Errorf("empty URL")
	case u.Scheme != "https":
		return fmt.Errorf("%q: scheme must be https", u.Redacted())
	case u.Hostname() == "":
		return fmt.Errorf("%q: no host", u.Redacted())
	case u.User != nil:
		return fmt.Errorf("%q: user info not allowed", u.Redacted())
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
		return fmt.Errorf("%q: query or fragment not allowed", u.Redacted())
	}
	return nil
}

// FilterControllerURLs returns the acceptable URLs from a controller-supplied
// list (see CheckControllerURL), without duplicates and in their original
// order, plus one problem description per rejected entry.
func FilterControllerURLs(urls []*url.URL) (valid []*url.URL, rejected []string) {
	seen := make(map[string]bool, len(urls))
	for _, u := range urls {
		if err := CheckControllerURL(u); err != nil {
			rejected = append(rejected, err.Error())
			continue
		}
		key := u.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		valid = append(valid, u)
	}
	return valid, rejected
}

// FilterControllerURLStrings is FilterControllerURLs for string URLs; an
// entry that does not parse is rejected.
func FilterControllerURLStrings(urls []string) (valid []string, rejected []string) {
	parsed := make([]*url.URL, 0, len(urls))
	for _, s := range urls {
		u, err := url.Parse(s)
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("unparseable URL: %v", err))
			continue
		}
		parsed = append(parsed, u)
	}
	ok, bad := FilterControllerURLs(parsed)
	for _, u := range ok {
		valid = append(valid, u.String())
	}
	return valid, append(rejected, bad...)
}
