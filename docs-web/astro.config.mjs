// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightClientMermaid from '@pasqal-io/starlight-client-mermaid';
import sitemap from '@astrojs/sitemap';
import starlightThemeGalaxy from 'starlight-theme-galaxy';

// https://astro.build/config
export default defineConfig({
	site: 'https://autentico.top',
	integrations: [
		sitemap(),
		starlight({
			head: [
				{
					tag: 'script',
					attrs: {
						src: 'https://www.googletagmanager.com/gtag/js?id=G-B4MMCJ2QP2',
						async: true,
					},
				},
				{
					tag: 'script',
					content: `
						window.dataLayer = window.dataLayer || [];
						function gtag(){dataLayer.push(arguments);}
						gtag('js', new Date());
						gtag('config', 'G-B4MMCJ2QP2');
					`,
				},
			],
			title: 'Autentico',
			description: 'Documentation for the Autentico OAuth 2.0 / OpenID Connect Identity Provider',
			favicon: '/favicon.svg',
			logo: {
				src: './src/assets/logo.svg',
			},
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/eugenioenko/autentico' },
			],
			editLink: {
				baseUrl: 'https://github.com/eugenioenko/autentico/edit/main/docs-web/',
			},
			plugins: [starlightThemeGalaxy(), starlightClientMermaid()],
			sidebar: [
				{ label: 'Introduction', link: '/' },
				{
					label: 'Getting Started',
					items: [
						{ label: 'Quickstart', link: '/getting-started/quickstart/' },
						{ label: 'Installation', link: '/getting-started/installation/' },
					],
				},
				{
					label: 'Deployment',
					items: [
						{ label: 'Binary', link: '/deployment/binary/' },
						{ label: 'Docker', link: '/deployment/docker/' },
						{ label: 'Docker Compose', link: '/deployment/docker-compose/' },
						{ label: 'Reverse Proxy', link: '/deployment/reverse-proxy/' },
						{ label: 'Database Migrations', link: '/deployment/migrations/' },
						{ label: 'Key Generation', link: '/deployment/key-generation/' },
						{ label: 'Production Checklist', link: '/deployment/production-checklist/' },
					],
				},
				{
					label: 'Configuration',
					items: [
						{ label: 'Overview', link: '/configuration/overview/' },
						{ label: 'Bootstrap Settings (.env)', link: '/configuration/bootstrap/' },
						{ label: 'Runtime Settings', link: '/configuration/runtime-settings/' },
						{ label: 'Per-Client Overrides', link: '/configuration/per-client-overrides/' },
					],
				},
				{
					label: 'Authentication',
					items: [
						{ label: 'Overview', link: '/authentication/overview/' },
						{ label: 'Password', link: '/authentication/password/' },
						{ label: 'Passkeys (WebAuthn)', link: '/authentication/passkeys/' },
						{ label: 'MFA', link: '/authentication/mfa/' },
						{ label: 'Trusted Devices', link: '/authentication/trusted-devices/' },
						{ label: 'SSO Sessions', link: '/authentication/sso-sessions/' },
					],
				},
				{
					label: 'Protocol Reference',
					items: [
						{ label: 'Overview', link: '/protocol/overview/' },
						{ label: 'Authorization Code + PKCE', link: '/protocol/authorization-code/' },
						{ label: 'Refresh Tokens', link: '/protocol/refresh-tokens/' },
						{ label: 'ROPC', link: '/protocol/ropc/' },
						{ label: 'Token Structure & Claims', link: '/protocol/token-structure/' },
						{ label: 'Scopes', link: '/protocol/scopes/' },
						{ label: 'OIDC Discovery', link: '/protocol/oidc-discovery/' },
						{ label: 'Introspection & Revocation', link: '/protocol/introspection-revocation/' },
					],
				},
				{
					label: 'Clients',
					items: [
						{ label: 'Overview', link: '/clients/overview/' },
						{ label: 'Registering a Client', link: '/clients/registering/' },
						{ label: 'Client Types', link: '/clients/client-types/' },
						{ label: 'Per-Client Configuration', link: '/clients/per-client-configuration/' },
					],
				},
				{
					label: 'Users',
					items: [
						{ label: 'Overview', link: '/users/overview/' },
						{ label: 'User Model', link: '/users/user-model/' },
						{ label: 'Managing Users', link: '/users/managing-users/' },
						{ label: 'Self-Signup', link: '/users/self-signup/' },
						{ label: 'Account Lockout', link: '/users/account-lockout/' },
					],
				},
				{
					label: 'Admin UI',
					items: [
						{ label: 'Overview', link: '/admin-ui/overview/' },
						{ label: 'Dashboard', link: '/admin-ui/dashboard/' },
						{ label: 'Users', link: '/admin-ui/users/' },
						{ label: 'Clients', link: '/admin-ui/clients/' },
						{ label: 'Sessions', link: '/admin-ui/sessions/' },
						{ label: 'Settings', link: '/admin-ui/settings/' },
					],
				},
				{
					label: 'Integrate',
					items: [
						{ label: 'Connecting an OIDC Client', link: '/integrate/connecting/' },
						{ label: 'Client Libraries', link: '/integrate/client-libraries/' },
						{ label: 'PKCE Flow Walkthrough', link: '/integrate/pkce-walkthrough/' },
						{ label: 'Verifying Tokens', link: '/integrate/verifying-tokens/' },
						{ label: 'Test Fixture', link: '/integrate/test-fixture/' },
					],
				},
				{
					label: 'Security',
					items: [
						{ label: 'Hardening', link: '/security/overview/' },
						{ label: 'Incident Response', link: '/security/incident-response/' },
					],
				},
				{
					label: 'API Reference',
					items: [
						{ label: 'Endpoints', link: '/api-reference/endpoints/' },
					],
				},
				{
					label: 'Architecture',
					items: [
						{ label: 'Package Structure', link: '/architecture/package-structure/' },
						{ label: 'Database Schema', link: '/architecture/database-schema/' },
						{ label: 'Design Decisions', link: '/architecture/design-decisions/' },
						{ label: 'Performance & Capacity', link: '/architecture/performance/' },
					],
				},
			],
			customCss: ['./src/styles/custom.css'],
		}),
	],
});
