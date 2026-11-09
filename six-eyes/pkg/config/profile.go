package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type Profile struct {
	Name        string `yaml:"name"`
	Strategy    string `yaml:"strategy"`
	SplitOffset int    `yaml:"split_offset"`
	FakeRstTTL  int    `yaml:"fake_rst_ttl"`
	EnableBadChecksum bool `yaml:"enable_bad_checksum"`
	TargetPort  int    `yaml:"target_port"`
}

func DefaultProfile() *Profile {
	return &Profile{
		Name:              "six-eyes-stealth",
		Strategy:          "FAKE_RST",
		SplitOffset:       2,
		FakeRstTTL:        3,
		EnableBadChecksum: true,
		TargetPort:        443,
	}
}

func LoadProfile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
