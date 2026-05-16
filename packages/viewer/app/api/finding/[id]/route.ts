import { NextResponse } from 'next/server';
import { findFindingById } from '@/app/lib/state';

export const dynamic = 'force-dynamic';

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const hit = findFindingById(id);
  if (!hit) {
    return NextResponse.json({ error: 'finding not found' }, { status: 404 });
  }
  return NextResponse.json({
    finding: hit.finding,
    file: {
      filePath: hit.file.filePath,
      status: hit.file.status,
      contentHash: hit.file.contentHash,
    },
  });
}
