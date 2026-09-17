#!/usr/bin/env python3
"""csv2parquet.py —— 把 run_all.sh 产出的 CSV 转成 Parquet / DuckDB。

**默认不改动、不删除任何原文件**，只在输出目录里新建 parquet/ 与（可选）analysis.duckdb。

用法
----
    python3 csv2parquet.py <输出目录>                  # CSV -> Parquet（<输出目录>/parquet/）
    python3 csv2parquet.py <输出目录> --duckdb          # 再额外打包成一个 analysis.duckdb
    python3 csv2parquet.py <输出目录> --only index,ocsp_batch
    python3 csv2parquet.py <输出目录> --replace         # 转完删掉原 CSV（会先确认）

依赖
----
    pip3 install duckdb                            # 普通环境
    pip3 install --break-system-packages duckdb    # PEP 668 受管环境（如 Ubuntu 24）
"""

import argparse
import glob
import os
import sys

try:
    import duckdb
except ImportError:
    sys.exit("缺少 duckdb，请先安装：\n"
             "    pip3 install duckdb\n"
             "    pip3 install --break-system-packages duckdb    # PEP 668 受管环境")


def q(name):
    """把表名安全地引起来（中文 / 空格 / 特殊字符都能用）"""
    return '"' + name.replace('"', '""') + '"'


def human(size):
    """字节 -> 可读"""
    for unit in ("B", "K", "M", "G"):
        if size < 1024 or unit == "G":
            return f"{size:.1f}{unit}" if unit != "B" else f"{size}B"
        size /= 1024


def main():
    ap = argparse.ArgumentParser(
        description="把 run_all.sh 产出的 CSV 转成 Parquet / DuckDB（默认不动原文件）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out_dir", help="run_all.sh 的输出目录（里面有 *.csv）")
    ap.add_argument("--duckdb", action="store_true",
                    help="额外把各表打包成一个 <输出目录>/analysis.duckdb")
    ap.add_argument("--replace", action="store_true",
                    help="转换成功后删除原 CSV（会先要求确认）")
    ap.add_argument("--yes", action="store_true", help="配合 --replace，跳过确认直接删")
    ap.add_argument("--only", help="只转换这几张表（逗号分隔的文件名主干，如 index,ocsp_batch）")
    ap.add_argument("--out", help="Parquet 输出目录（默认 <输出目录>/parquet）")
    ap.add_argument("--varchar", action="store_true",
                    help="所有列按字符串存储（避免类型推断意外，压缩仍然很好）")
    ap.add_argument("--force", action="store_true", help="已存在同名产物时覆盖")
    args = ap.parse_args()

    out_dir = os.path.abspath(os.path.expanduser(args.out_dir))
    if not os.path.isdir(out_dir):
        sys.exit(f"不是目录: {out_dir}")

    csvs = sorted(glob.glob(os.path.join(out_dir, "*.csv")))
    if not csvs:
        sys.exit(f"{out_dir} 下没有 .csv")

    if args.only:
        want = {s.strip() for s in args.only.split(",") if s.strip()}
        csvs = [p for p in csvs
                if os.path.splitext(os.path.basename(p))[0] in want]
        if not csvs:
            sys.exit(f"--only 没匹配到任何 CSV（可用: "
                     f"{', '.join(os.path.splitext(os.path.basename(p))[0] for p in sorted(glob.glob(os.path.join(out_dir, '*.csv'))))}）")

    pq_dir = os.path.abspath(args.out) if args.out else os.path.join(out_dir, "parquet")
    os.makedirs(pq_dir, exist_ok=True)

    # 用文件库而不是内存库：duckdb 处理 GB 级数据会 spill 到磁盘，
    # 放在输出目录可避免撑爆 /tmp（很多机器上 /tmp 是小的 tmpfs）。
    if args.duckdb:
        db_path = os.path.join(out_dir, "analysis.duckdb")
        if os.path.exists(db_path) and not args.force:
            sys.exit(f"{db_path} 已存在（加 --force 覆盖）")
        tmp_db = None
    else:
        db_path = os.path.join(out_dir, ".csv2parquet_tmp.duckdb")
        tmp_db = db_path

    con = duckdb.connect(db_path)
    con.execute("SET preserve_insertion_order=false")

    print(f"输出目录: {out_dir}")
    print(f"Parquet : {pq_dir}")
    if args.duckdb:
        print(f"DuckDB  : {db_path}")
    print(f"待转换  : {len(csvs)} 个 CSV\n")

    done = []
    for path in csvs:
        stem = os.path.splitext(os.path.basename(path))[0]
        dst = os.path.join(pq_dir, stem + ".parquet")
        if os.path.exists(dst) and not args.force:
            print(f"  跳过（已存在）: {stem}")
            continue

        csv_sz = os.path.getsize(path)
        typ = ", all_varchar=true" if args.varchar else ""
        con.execute(f"CREATE OR REPLACE TABLE {q(stem)} AS "
                    f"SELECT * FROM read_csv_auto('{path}', header=true{typ})")

        # CSV 是 utf-8-sig（带 BOM），DuckDB 会把首列名读成 "\ufeffcert"，改回来
        first = con.execute(f"DESCRIBE {q(stem)}").fetchall()[0][0]
        if first.startswith("\ufeff"):
            con.execute(f"ALTER TABLE {q(stem)} RENAME COLUMN {q(first)} "
                        f"TO {q(first.lstrip(chr(0xfeff)))}")

        n = con.execute(f"SELECT count(*) FROM {q(stem)}").fetchone()[0]
        con.execute(f"COPY {q(stem)} TO '{dst}' (FORMAT PARQUET, COMPRESSION ZSTD)")
        pq_sz = os.path.getsize(dst)
        ratio = csv_sz / pq_sz if pq_sz else 0
        print(f"  {stem:<26} {n:>9,} 行   "
              f"{csv_sz/1048576:>7.1f} M -> {pq_sz/1048576:>7.2f} M   {ratio:>6.1f}x")
        done.append((path, stem, n, csv_sz, pq_sz))
        if not args.duckdb:
            con.execute(f"DROP TABLE {q(stem)}")   # 只要 parquet 时及时释放

    con.close()

    if tmp_db and os.path.exists(tmp_db):
        os.remove(tmp_db)

    if not done:
        print("\n没有转换任何文件")
        return

    tot_csv = sum(x[3] for x in done)
    tot_pq = sum(x[4] for x in done)
    print(f"\n合计: {len(done)} 张表，"
          f"{tot_csv/1048576:.0f} M -> {tot_pq/1048576:.1f} M，"
          f"压缩比 {tot_csv/tot_pq:.1f}x（省下 {(tot_csv-tot_pq)/1048576:.0f} M）")
    if args.duckdb:
        db_sz = os.path.getsize(db_path)
        print(f"DuckDB 库: {db_path}（{db_sz/1048576:.0f} M）")

    if args.replace:
        if not args.yes:
            print("\n即将删除以下原 CSV（Parquet 已生成）:")
            for path, stem, *_ in done:
                print(f"  {path}")
            ans = input("\n确认删除请输入 yes（其它任意输入取消）: ").strip().lower()
            if ans != "yes":
                print("已取消，原 CSV 保留")
                return
        for path, stem, *_ in done:
            os.remove(path)
            print(f"  已删除: {os.path.basename(path)}")
        print("完成（原 CSV 已删除）")


if __name__ == "__main__":
    main()
