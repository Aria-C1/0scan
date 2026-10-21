"""Flask Web 应用：异步扫描任务 + 进度轮询 + 扫描历史 + 报告下载。

架构：
- ``POST /scan``   —— 无 JS 回退路径：同步执行完直接重定向到报告页；
- ``POST /api/scan`` —— 创建任务返回 job_id，后台线程执行；
- ``GET /api/status/<id>`` —— 前端 800ms 轮询，展示克隆/扫描阶段与进度；
- ``GET /report/<id>`` —— HTML 报告页；
- ``GET /api/report/<id>?format=html|json|sarif`` —— 报告下载。

任务保存在内存（重启即清空，最近 20 条），单机工具场景够用。
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

from .history import scan_history
from .repo import RepoError, classify_target, fetch_repo
from .report import render_html, render_json, render_sarif
from .scanner import ScanResult, Scanner

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_MAX_JOBS = 20


@dataclass
class Job:
    """一次扫描任务（内存模型）。"""

    id: str
    target: str
    full_history: bool = False
    created_at: float = 0.0
    state: str = "running"  # running | done | error
    stage: str = "排队中"  # 克隆仓库 | 扫描文件 | 扫描历史 | 完成
    detail: str = ""
    scanned_files: int = 0
    result: ScanResult | None = None
    error: str = ""


def create_app() -> Flask:
    """创建并配置 0scan Web 应用（应用工厂模式，便于测试）。"""
    app = Flask(__name__, template_folder=str(_TEMPLATE_DIR))
    jobs: "OrderedDict[str, Job]" = OrderedDict()
    lock = threading.Lock()

    # ---- 任务管理 ----

    def _register(job: Job) -> None:
        with lock:
            jobs[job.id] = job
            while len(jobs) > _MAX_JOBS:
                finished = next(
                    (jid for jid, j in jobs.items() if j.state != "running"), None
                )
                if finished is None:
                    break
                del jobs[finished]

    def _execute(job: Job) -> None:
        try:
            job.stage = "克隆仓库"
            with fetch_repo(job.target, full_history=job.full_history) as repo_dir:
                job.stage = "扫描文件"

                def _progress(scanned: int, current: str) -> None:
                    job.scanned_files = scanned
                    job.detail = current

                scanner = Scanner(progress_cb=_progress)
                result = scanner.scan_path(repo_dir, target_label=job.target)
                if job.full_history and (repo_dir / ".git").is_dir():
                    job.stage = "扫描历史"
                    history_findings, history_errors = scan_history(
                        repo_dir, scanner.detectors, scanner.limits
                    )
                    result.findings.extend(history_findings)
                    result.errors.extend(history_errors)
            job.result = result
            job.state = "done"
            job.stage = "完成"
        except RepoError as exc:
            job.state = "error"
            job.error = str(exc)
        except Exception as exc:  # 兜底：单任务失败不拖垮服务
            job.state = "error"
            job.error = f"内部错误：{exc}"

    def _new_job(raw: str, full_history: bool) -> Job:
        return Job(
            id=secrets.token_hex(6),
            target=raw.strip() or "demo",
            full_history=full_history,
            created_at=time.time(),
        )

    def _get(job_id: str) -> Job | None:
        with lock:
            return jobs.get(job_id)

    # ---- 页面 ----

    @app.route("/")
    def index():
        with lock:
            recent = [
                {
                    "id": job.id,
                    "target": job.target,
                    "state": job.state,
                    "full_history": job.full_history,
                    "findings": len(job.result.findings) if job.result else None,
                    "time": datetime.fromtimestamp(job.created_at).strftime("%H:%M"),
                }
                for job in reversed(jobs.values())
            ]
        return render_template("index.html", jobs=recent)

    @app.route("/scan", methods=["POST"])
    def scan():
        """无 JS 回退：同步执行完成后重定向到报告页。"""
        raw = request.form.get("url", "")
        full = request.form.get("full_history") == "1"
        try:
            classify_target(raw)
        except RepoError as exc:
            return render_template("error.html", message=str(exc)), 400
        job = _new_job(raw, full)
        _register(job)
        _execute(job)  # 阻塞执行（浏览器等待期间无进度，与旧版一致）
        if job.state == "error":
            return render_template("error.html", message=job.error), 400
        return redirect(url_for("report_page", job_id=job.id))

    @app.route("/report/<job_id>")
    def report_page(job_id: str):
        job = _get(job_id)
        if job is None:
            return render_template("error.html", message="任务不存在或已被清理。"), 404
        if job.state == "error":
            return render_template("error.html", message=job.error), 400
        if job.state != "done":
            return redirect("/")
        return render_template("report.html", result=job.result, web_mode=True, job_id=job.id)

    # ---- API ----

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        payload = request.get_json(silent=True) or request.form
        raw = (payload.get("url") or "").strip()
        full = str(payload.get("full_history", "")) in ("1", "true", "True", "on")
        try:
            classify_target(raw)
        except RepoError as exc:
            return jsonify({"error": str(exc)}), 400
        job = _new_job(raw, full)
        _register(job)
        threading.Thread(target=_execute, args=(job,), daemon=True).start()
        return jsonify({"job_id": job.id})

    @app.route("/api/status/<job_id>")
    def api_status(job_id: str):
        job = _get(job_id)
        if job is None:
            return jsonify({"error": "任务不存在"}), 404
        return jsonify(
            {
                "id": job.id,
                "state": job.state,
                "stage": job.stage,
                "detail": job.detail,
                "scanned_files": job.scanned_files,
                "findings": len(job.result.findings) if job.result else None,
                "error": job.error or None,
            }
        )

    @app.route("/api/report/<job_id>")
    def api_report(job_id: str):
        job = _get(job_id)
        if job is None:
            return jsonify({"error": "任务不存在"}), 404
        if job.state != "done":
            return jsonify({"error": "任务尚未完成"}), 409
        fmt = request.args.get("format", "html")
        if fmt == "json":
            return Response(
                render_json(job.result),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename=zeroscan-{job.id}.json"},
            )
        if fmt == "sarif":
            return Response(
                render_sarif(job.result),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment; filename=zeroscan-{job.id}.sarif"},
            )
        return Response(
            render_html(job.result, web_mode=False),
            mimetype="text/html",
            headers={"Content-Disposition": f"attachment; filename=zeroscan-{job.id}.html"},
        )

    return app
