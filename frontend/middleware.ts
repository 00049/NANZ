// WHAT THIS FILE DOES: Next.js edge middleware that protects /report/* and /account/*
// routes. Unauthenticated users are redirected to /?auth=required with their intended
// URL saved in a cookie so they can be redirected after sign-in.
// KEY DEPENDENCIES: next/server
// MOCKED DATA: None — reads JWT token from localStorage-synced cookie 'nanz-auth-token'

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const PROTECTED_ROUTES = [
  '/account',
  '/account/settings',
  '/account/scans',
  '/account/subscription',
];

// Report pages are publicly accessible — no payment required.
// /scan/[scanId] is intentionally public.

function isProtected(pathname: string): boolean {
  return PROTECTED_ROUTES.some((route) => pathname === route || pathname.startsWith(route + '/'));
}

export function middleware(request: NextRequest) {
  const { pathname, searchParams } = request.nextUrl;

  if (!isProtected(pathname)) {
    return NextResponse.next();
  }

  // Check for auth token — Zustand persists to localStorage, but middleware
  // runs on the edge (no localStorage). We use a cookie set by the auth flow.
  // The cookie 'nanz_auth_token' is set in AuthModal on successful sign-in.
  const authCookie = request.cookies.get('nanz_auth_token');
  const hasToken = Boolean(authCookie?.value);

  if (!hasToken) {
    const redirectUrl = request.nextUrl.clone();
    redirectUrl.pathname = '/';
    redirectUrl.searchParams.set('auth', 'required');

    const response = NextResponse.redirect(redirectUrl);
    // Save intended destination for post-login redirect
    response.cookies.set('redirect_after_login', pathname, {
      httpOnly: false,
      maxAge: 60 * 10, // 10 minutes
      path: '/',
    });

    return response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/account/:path*',
    // /report is NOT in matcher — handled inline with useReportAccess to avoid UX loops
  ],
};
