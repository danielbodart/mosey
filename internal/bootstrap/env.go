package bootstrap

// ClientEnv is the ClientLine's env (§6.2): each allow-listed variable
// that is set to a value the line can carry. A value that cannot travel
// as it is (empty, over 64 bytes, or holding any byte outside the line's
// small alphabet) is left out, never escaped, and named in dropped so the
// client can log it.
func ClientEnv(getenv func(string) string) (env map[string]string, dropped []string) {
	env = map[string]string{}
	for _, name := range EnvNames {
		v := getenv(name)
		switch {
		case v == "":
		case ValidEnvValue(v):
			env[name] = v
		default:
			dropped = append(dropped, name)
		}
	}
	return env, dropped
}
