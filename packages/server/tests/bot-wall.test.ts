// Tests for `classifyBotWall` — the shared bot-wall / CAPTCHA detector
// promoted into `@fetchproxy/server` (#86).
//
// The cohort kept reinventing per-portal detection. Misclassifying a
// bot-wall as "not found" is the silent-data-corruption failure class
// rounds 2-3 stamped out, so detection lives here once, keyed on the
// BODY primarily (a PerimeterX interstitial can be served as HTTP 200
// — zillow #91 caught this), with status/headers as additional signal.
import { describe, it, expect } from 'vitest';
import { classifyBotWall } from '../src/index.js';

// Real-shaped interstitial bodies. Trimmed to the load-bearing markers
// but otherwise the shape a portal actually serves.
const PX_BODY = `<!DOCTYPE html><html lang="en"><head>
  <meta name="px-captcha" content="">
  <title>Access to this page has been denied</title>
</head><body>
  <div id="px-captcha"></div>
  <script>window._pxAppId = "PXxxxxxxxx"; window._pxJsClientSrc = "/xxxx/init.js";</script>
  <h1>Access to this page has been denied</h1>
</body></html>`;

const AWS_WAF_BODY = `<!DOCTYPE html><html><head><title>Just a moment...</title></head>
<body><div id="challenge"></div>
<script type="text/javascript" src="https://xxxx.token.awswaf.com/xxxx/challenge.js"></script>
<script>AwsWafIntegration.checkForceRefresh();</script>
<form id="AWSWAFCAPTCHA"></form>
</body></html>`;

const CLOUDFLARE_BODY = `<!DOCTYPE html><html><head>
<title>Attention Required! | Cloudflare</title></head>
<body><div class="cf-error-details">
<h1>Sorry, you have been blocked</h1>
<p>You are unable to access this website</p></div>
<div class="cf-wrapper">Ray ID: 8xxxxxxxxxxxxxxx</div>
</body></html>`;

const DATADOME_BODY = `<!DOCTYPE html><html><head><title>Blocked</title></head>
<body><script>var dd={'rt':'c','cid':'xxxx'};</script>
<script src="https://geo.captcha-delivery.com/captcha/?initialCid=xxxx"></script>
<div id="datadome-captcha"></div>
</body></html>`;

// A normal SSR listing page — must NOT be flagged. Mentions "captcha"
// nowhere; this is the false-positive guard.
const NORMAL_LISTING = `<!DOCTYPE html><html><head><title>123 Main St | $750,000 | 3 bd 2 ba</title></head>
<body><main><h1>123 Main St, Springfield</h1>
<div class="price">$750,000</div>
<section class="facts">3 beds · 2 baths · 1,800 sqft</section>
<a href="/user/login">Sign in</a>
</main></body></html>`;

describe('classifyBotWall', () => {
  describe('PerimeterX', () => {
    it('detects the px interstitial served as HTTP 200 (body-keyed)', () => {
      // zillow #91: PerimeterX sometimes serves the CAPTCHA with a 200
      // status, so detection must not require a 4xx.
      expect(classifyBotWall(PX_BODY, 200)).toEqual({
        blocked: true,
        vendor: 'perimeterx',
      });
    });

    it('detects px on a 403 too', () => {
      expect(classifyBotWall(PX_BODY, 403)).toEqual({
        blocked: true,
        vendor: 'perimeterx',
      });
    });

    it.each([
      ['window._pxAppId', '<html><script>window._pxAppId="PX1"</script></html>'],
      ['meta px-captcha', '<html><head><meta name="px-captcha" content=""></head></html>'],
      [
        'access-denied phrase',
        '<html><body>Access to this page has been denied</body></html>',
      ],
    ])('matches on the %s marker alone', (_label, body) => {
      expect(classifyBotWall(body, 200)).toEqual({
        blocked: true,
        vendor: 'perimeterx',
      });
    });
  });

  describe('AWS WAF', () => {
    it('detects via the x-amzn-waf-action header on a 403', () => {
      expect(
        classifyBotWall('', 403, { 'x-amzn-waf-action': 'challenge' }),
      ).toEqual({ blocked: true, vendor: 'aws_waf' });
    });

    it('detects via AWSWAFCAPTCHA challenge HTML on a 403', () => {
      expect(classifyBotWall(AWS_WAF_BODY, 403)).toEqual({
        blocked: true,
        vendor: 'aws_waf',
      });
    });

    it('detects via the awswaf token-host marker on a 403', () => {
      const body = '<script src="https://x.token.awswaf.com/x/challenge.js"></script>';
      expect(classifyBotWall(body, 403)).toEqual({
        blocked: true,
        vendor: 'aws_waf',
      });
    });

    it('does NOT flag AWS-WAF body markers on a 200 (waf challenges are 4xx)', () => {
      // The AWS-WAF arm requires the 403 signal — without it a 200 page
      // that merely references awswaf must not trip the wall.
      expect(classifyBotWall(AWS_WAF_BODY, 200)).toEqual({ blocked: false });
    });
  });

  describe('Cloudflare', () => {
    it('detects via the cf-mitigated header', () => {
      expect(
        classifyBotWall('', 403, { 'cf-mitigated': 'challenge' }),
      ).toEqual({ blocked: true, vendor: 'cloudflare' });
    });

    it('detects via the "Attention Required!" title in the body', () => {
      expect(classifyBotWall(CLOUDFLARE_BODY, 403)).toEqual({
        blocked: true,
        vendor: 'cloudflare',
      });
    });
  });

  describe('DataDome', () => {
    it('detects via the captcha-delivery challenge marker', () => {
      expect(classifyBotWall(DATADOME_BODY, 200)).toEqual({
        blocked: true,
        vendor: 'datadome',
      });
    });
  });

  describe('clean pages', () => {
    it('returns blocked:false on a normal 200 listing page', () => {
      expect(classifyBotWall(NORMAL_LISTING, 200)).toEqual({ blocked: false });
    });

    it('returns blocked:false on a 403 with no bot-wall markers', () => {
      // A plain 403 (e.g. an API auth error) is NOT a bot-wall — it must
      // stay distinguishable so callers don't back off on a hard 403.
      expect(classifyBotWall('{"error":"forbidden"}', 403)).toEqual({
        blocked: false,
      });
    });

    it('returns blocked:false on an empty body / 200', () => {
      expect(classifyBotWall('', 200)).toEqual({ blocked: false });
    });
  });

  describe('header case-insensitivity', () => {
    it('matches a capitalised X-Amzn-Waf-Action header', () => {
      expect(
        classifyBotWall('', 403, { 'X-Amzn-Waf-Action': 'count' }),
      ).toEqual({ blocked: true, vendor: 'aws_waf' });
    });
  });

  describe('precedence', () => {
    it('prefers PerimeterX over a generic header when both present', () => {
      // px is the body-keyed, most-specific signal; it wins.
      expect(
        classifyBotWall(PX_BODY, 200, { 'cf-mitigated': 'challenge' }),
      ).toEqual({ blocked: true, vendor: 'perimeterx' });
    });
  });
});
