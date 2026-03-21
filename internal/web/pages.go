package web

import _ "embed"

//go:embed login.html
var LoginHTML string

//go:embed dashboard.html
var DashboardHTML string

//go:embed tools.html
var ToolsHTML string

//go:embed infra.html
var InfraHTML string

//go:embed qrlanding.html
var QRLandingHTML string

//go:embed intunelanding.html
var IntuneLandingHTML string
