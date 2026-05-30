import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { toCsv, downloadCsv, downloadJson, downloadText, dateStamp, type CsvColumn } from '../csv';

interface Row {
  name: string;
  count: number;
}

const columns: CsvColumn<Row>[] = [
  { header: 'Name', value: (r) => r.name },
  { header: 'Count', value: (r) => r.count },
];

describe('toCsv', () => {
  it('emits a header row first', () => {
    const csv = toCsv<Row>([], columns);
    expect(csv).toBe('Name,Count');
  });

  it('joins rows with CRLF line endings', () => {
    const csv = toCsv<Row>([{ name: 'a', count: 1 }, { name: 'b', count: 2 }], columns);
    expect(csv).toBe('Name,Count\r\na,1\r\nb,2');
  });

  it('quotes fields containing comma, quote, newline, or carriage return and doubles quotes', () => {
    const csv = toCsv<Row>(
      [
        { name: 'has,comma', count: 1 },
        { name: 'has"quote', count: 2 },
        { name: 'has\nnewline', count: 3 },
        { name: 'has\rcr', count: 4 },
      ],
      columns
    );
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe('"has,comma",1');
    expect(lines[2]).toBe('"has""quote",2');
    expect(lines[3]).toBe('"has\nnewline",3');
    expect(lines[4]).toBe('"has\rcr",4');
  });

  it('does not quote plain fields', () => {
    const csv = toCsv<Row>([{ name: 'plain', count: 42 }], columns);
    expect(csv).toBe('Name,Count\r\nplain,42');
  });

  it('neutralizes spreadsheet formula-injection by prefixing a single quote', () => {
    const csv = toCsv<Row>(
      [
        { name: '=HYPERLINK("http://evil","x")', count: 1 },
        { name: '+1', count: 2 },
        { name: '-1', count: 3 },
        { name: '@x', count: 4 },
        { name: '\tlead-tab', count: 5 },
      ],
      columns
    );
    const lines = csv.split('\r\n');
    // The = field also contains commas/quotes, so it is RFC-4180 quoted on top.
    expect(lines[1]).toBe('"\'=HYPERLINK(""http://evil"",""x"")",1');
    expect(lines[2]).toBe("'+1,2");
    expect(lines[3]).toBe("'-1,3");
    expect(lines[4]).toBe("'@x,4");
    // A leading tab triggers both the formula guard and (\t is not in NEEDS_QUOTING) no quoting.
    expect(lines[5]).toBe("'\tlead-tab,5");
  });

  it('does not quote negative (or other) numeric values — only strings can be formula payloads', () => {
    // Regression: a numeric column value like a -0.5 proximity delta must export
    // as the number -0.5, not the text "'-0.5" (which breaks sum/sort in Excel).
    const csv = toCsv<Row>([{ name: 'decayed', count: -0.5 as unknown as number }], columns);
    expect(csv.split('\r\n')[1]).toBe('decayed,-0.5');
  });

  it('leaves benign values that merely contain +/-/=/@ mid-string unchanged', () => {
    const csv = toCsv<Row>([{ name: 'a=b', count: 1 }, { name: 'x-y', count: 2 }], columns);
    const lines = csv.split('\r\n');
    expect(lines[1]).toBe('a=b,1');
    expect(lines[2]).toBe('x-y,2');
  });
});

describe('downloadCsv', () => {
  beforeEach(() => {
    // jsdom does not implement the URL object-URL API; provide stubs to spy on.
    if (typeof URL.createObjectURL !== 'function') {
      URL.createObjectURL = () => 'blob:stub';
    }
    if (typeof URL.revokeObjectURL !== 'function') {
      URL.revokeObjectURL = () => {};
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('creates and clicks an <a download> then revokes the object URL with a UTF-8 BOM blob', () => {
    const createSpy = vi
      .spyOn(URL, 'createObjectURL')
      .mockReturnValue('blob:fake');
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {});

    downloadCsv('augur-test.csv', 'Name,Count\r\na,1');

    expect(createSpy).toHaveBeenCalledTimes(1);
    const blob = createSpy.mock.calls[0][0] as Blob;
    expect(blob.type).toBe('text/csv;charset=utf-8');
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(revokeSpy).toHaveBeenCalledWith('blob:fake');
  });

  it('prefixes the blob content with a UTF-8 BOM', async () => {
    let captured: Blob | null = null;
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b: Blob | MediaSource) => {
      captured = b as Blob;
      return 'blob:fake';
    });
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    downloadCsv('augur-test.csv', 'Name\r\na');
    const buf = await new Promise<ArrayBuffer>((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result as ArrayBuffer);
      fr.onerror = () => reject(fr.error);
      fr.readAsArrayBuffer(captured!);
    });
    const bytes = new Uint8Array(buf);
    // UTF-8 BOM is EF BB BF, then the ASCII "Name..."
    expect([bytes[0], bytes[1], bytes[2]]).toEqual([0xef, 0xbb, 0xbf]);
    expect(String.fromCharCode(bytes[3])).toBe('N');
  });
});

describe('dateStamp', () => {
  it('returns a YYYY-MM-DD local-clock stamp', () => {
    expect(dateStamp()).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});

describe('downloadJson', () => {
  beforeEach(() => {
    if (typeof URL.createObjectURL !== 'function') URL.createObjectURL = () => 'blob:stub';
    if (typeof URL.revokeObjectURL !== 'function') URL.revokeObjectURL = () => {};
  });
  afterEach(() => vi.restoreAllMocks());

  it('creates and clicks an <a download> then revokes, with an application/json blob', async () => {
    let captured: Blob | null = null;
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockImplementation((b: Blob | MediaSource) => {
      captured = b as Blob;
      return 'blob:fake';
    });
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    downloadJson('augur-test.json', { name: 'x', techniques: [] });

    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(captured!.type).toBe('application/json');
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(revokeSpy).toHaveBeenCalledWith('blob:fake');
    const text = await new Promise<string>((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result as string);
      fr.onerror = () => reject(fr.error);
      fr.readAsText(captured!);
    });
    expect(JSON.parse(text)).toEqual({ name: 'x', techniques: [] });
  });
});

describe('downloadText', () => {
  const realCreate = URL.createObjectURL;
  const realRevoke = URL.revokeObjectURL;
  beforeEach(() => {
    URL.createObjectURL = vi.fn(() => 'blob:mock');
    URL.revokeObjectURL = vi.fn();
  });
  afterEach(() => {
    URL.createObjectURL = realCreate;
    URL.revokeObjectURL = realRevoke;
  });

  it('creates a blob with the given mime and triggers a download', () => {
    const clickSpy = vi.fn();
    const anchor = { href: '', download: '', click: clickSpy, remove: vi.fn() } as unknown as HTMLAnchorElement;
    const createSpy = vi.spyOn(document, 'createElement').mockReturnValue(anchor);
    vi.spyOn(document.body, 'appendChild').mockImplementation((n) => n);

    downloadText('rule.yml', 'title: x\n', 'text/yaml');

    expect(URL.createObjectURL).toHaveBeenCalledOnce();
    expect(anchor.download).toBe('rule.yml');
    expect(clickSpy).toHaveBeenCalledOnce();
    createSpy.mockRestore();
  });
});
