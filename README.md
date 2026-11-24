# CNS Lab

My solutions to the CNS lab challenges. Each challenge folder has the challenge data, a solve script and a LaTeX write-up.

**Full report:** [report.pdf](https://github.com/kyanvde/cns-labo/blob/pdfs/report.pdf)

## Challenges

| Category | Challenge | Write-up |
| --- | --- | --- |
| Asymmetric encryption: ElGamal | [Asymmetric Nonsense](asymmetric_encryption_elgamal/asymmetric_nonsense) | [PDF](https://github.com/kyanvde/cns-labo/blob/pdfs/asymmetric_encryption_elgamal/asymmetric_nonsense/solution.pdf) |

## Layout

```
├── report.tex              # combined report, \subfile's every solution
├── latex/preamble.tex      # shared packages, listing style and macros
├── Makefile
└── <category>/<challenge>/
    ├── challenge.json      # challenge data
    ├── solve.py            # solve script, included in the write-up
    ├── solution.tex        # write-up, builds standalone or as part of report.tex
    └── README.md
```

## Building

The PDFs are built by GitHub Actions on every push to `main` and published to the [`pdfs`](https://github.com/kyanvde/cns-labo/tree/pdfs) branch.

To build locally (needs `latexmk` and a TeX Live with `subfiles` and `listings`):

```bash
make          # report.pdf and every solution.pdf
make clean    # remove build output
```

## Adding a challenge

1. Create `<category>/<challenge>/` with the challenge data and `solve.py`.
2. Add `solution.tex` starting with `\documentclass[../../report.tex]{subfiles}`.
3. Add `\subfile{<category>/<challenge>/solution}` to `report.tex`.
4. Add a row to the table above.
