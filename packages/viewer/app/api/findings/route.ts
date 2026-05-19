import { NextResponse } from "next/server";
import { loadViewerState } from "@/app/lib/state";

export const dynamic = "force-dynamic";

export async function GET() {
  const state = loadViewerState();
  return NextResponse.json({
    findings: state.findings,
  });
}
