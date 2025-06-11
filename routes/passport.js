const passport = require('passport');
const { Strategy: SamlStrategy } = require('@node-saml/passport-saml');

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

console.log('SAML Config:', {
  issuer: process.env.GREYTHR_SSO_ISSUER,
  entryPoint: process.env.GREYTHR_SSO_ENTRY_POINT,
  cert: process.env.GREYTHR_SSO_CERT ? '[Set]' : 'Missing',
  callbackUrl: `${process.env.APP_BASE_URL}/api/auth/greythr-sso/callback`,
  timestamp: new Date().toISOString(),
});

// Skip SAML strategy if cert is missing
if (!process.env.GREYTHR_SSO_CERT) {
  console.warn('WARNING: GREYTHR_SSO_CERT missing. SAML SSO disabled.');
  passport.use('saml', (req, res, next) => {
    console.log('SAML Disabled: Redirecting to error page.');
    return next(new Error('SAML SSO is disabled due to missing certificate.'));
  });
} else {
  passport.use(
    new SamlStrategy(
      {
        entryPoint: process.env.GREYTHR_SSO_ENTRY_POINT,
        issuer: process.env.GREYTHR_SSO_ISSUER,
        callbackUrl: `${process.env.APP_BASE_URL}/api/auth/greythr-sso/callback`,
        cert: process.env.GREYTHR_SSO_CERT || null, // Fallback to null
        protocol: 'https://',
        path: '/api/auth/greythr-sso/callback',
        identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:email',
        wantAssertionsSigned: false,
        wantAuthnResponseSigned: false,
        audience: process.env.GREYTHR_SSO_ISSUER,
        disableValidation: true, // Bypass cert validation (testing only)
      },
      (profile, done) => {
        console.log('SAML Profile:', { profile, timestamp: new Date().toISOString() });
        if (!profile.email && !profile['urn:oid:1.2.840.113549.1.9.1']) {
          console.error('SAML Error: No email in profile', { profile, timestamp: new Date().toISOString() });
          return done(new Error('No email provided by SAML provider'));
        }
        return done(null, {
          email: profile.email || profile['urn:oid:1.2.840.113549.1.9.1'],
          role: profile.role || 'employee',
        });
      }
    )
  );
}

module.exports = passport;