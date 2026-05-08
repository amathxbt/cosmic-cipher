import { NextRequest, NextResponse } from "next/server";
import { getValidToken } from "@/lib/auth";
import { OrbitportSeedResponse } from "@/types/orbitport";

const ORBITPORT_API_URL = process.env.ORBITPORT_API_URL;

export async function GET(req: NextRequest) {
  let usedFallback = false;
  let data: OrbitportSeedResponse | null = null;

  // cookieRes is a mutable carrier for Set-Cookie headers set by getValidToken.
  // Its cookies are forwarded onto the final JSON response below so they are
  // actually sent to the browser.  The original code discarded this object,
  // causing a new OAuth token to be fetched on every single request.
  const cookieRes = new NextResponse();

  try {
    if (!ORBITPORT_API_URL) throw new Error("Missing Orbitport API URL");

    // Get valid token — any new token's Set-Cookie header is written to cookieRes
    const accessToken = await getValidToken(req, cookieRes);
    if (!accessToken) {
      return NextResponse.json(
        { message: "Authentication failed" },
        { status: 401 }
      );
    }

    // Call downstream API with access token
    const response = await fetch(`${ORBITPORT_API_URL}/api/v1/services/trng`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Orbitport API error:", errorText);
      throw new Error(`API request failed: ${response.status}`);
    }

    data = await response.json();
  } catch (error) {
    console.warn("Using fallback random generation:", error);
    usedFallback = true;
    data = null;
  }

  const jsonRes = NextResponse.json({
    ...data,
    usedFallback,
  });

  // Forward any Set-Cookie headers from cookieRes onto the response that is
  // actually returned to the client.
  for (const cookie of cookieRes.headers.getSetCookie()) {
    jsonRes.headers.append("Set-Cookie", cookie);
  }

  return jsonRes;
}
