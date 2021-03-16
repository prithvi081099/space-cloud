package utils

// CreateToken create a token with primary secret
func (j *JWT) CreateToken(ctx context.Context, tokenClaims model.TokenClaims) (string, error) {
	j.lock.RLock()
	defer j.lock.RUnlock()

	claims := jwt.MapClaims{}
	for k, v := range tokenClaims {
		claims[k] = v
	}
	var tokenString string
	var err error
	// Add expiry of one week
	claims["exp"] = time.Now().Add(30 * time.Minute).Unix()
	for _, s := range j.staticSecrets {
		if s.IsPrimary {
			switch s.Alg {
			case config.RS256:
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				token.Header["kid"] = s.KID
				signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(s.PrivateKey))
				if err != nil {
					return "", err
				}
				tokenString, err = token.SignedString(signKey)
				if err != nil {
					return "", err
				}
				return tokenString, nil
			case config.HS256, "":
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				token.Header["kid"] = s.KID
				tokenString, err = token.SignedString([]byte(s.Secret))
				if err != nil {
					return "", err
				}
				return tokenString, nil
			default:
				return "", helpers.Logger.LogError(helpers.GetRequestID(ctx), fmt.Sprintf("Invalid algorithm (%s) provided for creating token", s.Alg), err, nil)
			}
		}