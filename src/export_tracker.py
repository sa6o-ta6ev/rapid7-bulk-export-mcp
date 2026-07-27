"""
Export Tracker Module

This module manages a separate DuckDB database to track Rapid7 export metadata,
allowing reuse of exports from the same day instead of creating new ones.
"""

import os
from datetime import date, datetime
from typing import Any, Dict, List, Optional

from .db_utils import duckdb_connection

DEFAULT_ORG_ID = "default"


class ExportTracker:
    """Tracks export metadata in a separate DuckDB database."""

    def __init__(self, db_path: str = "rapid7_bulk_export_tracking.db"):
        """
        Initialize the export tracker.

        Args:
            db_path: Path to the DuckDB database file for tracking exports
        """
        self.db_path = db_path
        new_file = not os.path.exists(db_path)
        self._initialize_db()
        if new_file:
            os.chmod(self.db_path, 0o600)

    def _initialize_db(self):
        """Initialize the export tracking database and create schema."""
        with duckdb_connection(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS exports (
                    export_id VARCHAR PRIMARY KEY,
                    export_date DATE NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    status VARCHAR NOT NULL,
                    file_count INTEGER,
                    row_count INTEGER,
                    parquet_urls VARCHAR[],
                    local_files VARCHAR[]
                )
            """)

            # Migrate schema: add export_type column for existing databases
            try:
                conn.execute("""
                    ALTER TABLE exports ADD COLUMN export_type VARCHAR DEFAULT 'vulnerability'
                """)
            except Exception:
                # Column already exists, ignore
                pass  # nosec B110

            # Migrate schema: add organization_id column for existing databases
            try:
                conn.execute("""
                    ALTER TABLE exports ADD COLUMN organization_id VARCHAR DEFAULT 'default'
                """)
            except Exception:
                # Column already exists, ignore
                pass  # nosec B110

            # Create index on export_date and export_type for fast lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_export_date_type
                ON exports(export_date, export_type)
            """)

            # Create composite index including organization_id for multi-tenant lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_export_date_type_org
                ON exports(export_date, export_type, organization_id)
            """)

    def get_today_export(
        self, export_type: str = "vulnerability", organization_id: str = DEFAULT_ORG_ID
    ) -> Optional[Dict[str, Any]]:
        """
        Get the most recent completed export from today.

        Args:
            export_type: Type of export to filter by (default: 'vulnerability')
            organization_id: Tenant scope to filter by (default: 'default',
                the single-tenant/unscoped store)

        Returns:
            Dictionary with export metadata if found, None otherwise
        """
        today = date.today()

        with duckdb_connection(self.db_path, read_only=True) as conn:
            result = conn.execute(
                """
                SELECT
                    export_id,
                    export_date,
                    created_at,
                    status,
                    file_count,
                    row_count,
                    parquet_urls,
                    local_files,
                    export_type,
                    organization_id
                FROM exports
                WHERE export_date = ?
                  AND status = 'COMPLETE'
                  AND export_type = ?
                  AND organization_id = ?
                ORDER BY created_at DESC
                LIMIT 1
            """,
                [today, export_type, organization_id],
            ).fetchone()

        if result:
            return {
                "export_id": result[0],
                "export_date": result[1],
                "created_at": result[2],
                "status": result[3],
                "file_count": result[4],
                "row_count": result[5],
                "parquet_urls": result[6],
                "local_files": result[7],
                "export_type": result[8],
                "organization_id": result[9],
            }

        return None

    def save_export(
        self,
        export_id: str,
        status: str,
        parquet_urls: List[str],
        local_files: Optional[List[str]] = None,
        row_count: Optional[int] = None,
        export_type: str = "vulnerability",
        organization_id: str = DEFAULT_ORG_ID,
    ):
        """
        Save or update export metadata.

        Args:
            export_id: The Rapid7 export ID
            status: Export status (COMPLETE, FAILED, etc.)
            parquet_urls: List of Parquet file URLs
            local_files: List of local file paths (optional)
            row_count: Number of rows loaded (optional)
            export_type: Type of export (default: 'vulnerability')
            organization_id: Tenant scope this export belongs to (default: 'default')
        """
        today = date.today()
        now = datetime.now()

        with duckdb_connection(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO exports (
                    export_id,
                    export_date,
                    created_at,
                    status,
                    file_count,
                    row_count,
                    parquet_urls,
                    local_files,
                    export_type,
                    organization_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (export_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    file_count = EXCLUDED.file_count,
                    row_count = EXCLUDED.row_count,
                    parquet_urls = EXCLUDED.parquet_urls,
                    local_files = EXCLUDED.local_files,
                    export_type = EXCLUDED.export_type,
                    organization_id = EXCLUDED.organization_id
            """,
                [
                    export_id,
                    today,
                    now,
                    status,
                    len(parquet_urls) if parquet_urls else 0,
                    row_count,
                    parquet_urls,
                    local_files,
                    export_type,
                    organization_id,
                ],
            )

    def get_export_by_id(self, export_id: str) -> Optional[Dict[str, Any]]:
        """
        Get export metadata by export ID.

        Args:
            export_id: The Rapid7 export ID

        Returns:
            Dictionary with export metadata if found, None otherwise
        """
        with duckdb_connection(self.db_path, read_only=True) as conn:
            result = conn.execute(
                """
                SELECT
                    export_id,
                    export_date,
                    created_at,
                    status,
                    file_count,
                    row_count,
                    parquet_urls,
                    local_files,
                    organization_id
                FROM exports
                WHERE export_id = ?
            """,
                [export_id],
            ).fetchone()

        if result:
            return {
                "export_id": result[0],
                "export_date": result[1],
                "created_at": result[2],
                "status": result[3],
                "file_count": result[4],
                "row_count": result[5],
                "parquet_urls": result[6],
                "local_files": result[7],
                "organization_id": result[8],
            }

        return None

    def list_exports(
        self, limit: int = 10, export_type: Optional[str] = None, organization_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List recent exports.

        Args:
            limit: Maximum number of exports to return
            export_type: Optional export type to filter by
            organization_id: Optional tenant scope to filter by

        Returns:
            List of export metadata dictionaries
        """
        sql = """
            SELECT export_id, export_date, created_at, status, file_count, row_count, export_type, organization_id
            FROM exports
        """
        conditions: list = []
        params: list = []
        if export_type is not None:
            conditions.append("export_type = ?")
            params.append(export_type)
        if organization_id is not None:
            conditions.append("organization_id = ?")
            params.append(organization_id)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with duckdb_connection(self.db_path, read_only=True) as conn:
            results = conn.execute(sql, params).fetchall()

        return [
            {
                "export_id": row[0],
                "export_date": row[1],
                "created_at": row[2],
                "status": row[3],
                "file_count": row[4],
                "row_count": row[5],
                "export_type": row[6],
                "organization_id": row[7],
            }
            for row in results
        ]

    def close(self):
        """No-op — connections are short-lived and released per-operation."""

    def purge(self):
        """Purge all tracking data by deleting the database file.

        Removes the database file and any associated WAL file from disk,
        then reinitializes with a fresh schema.
        """
        for suffix in ("", ".wal"):
            path = self.db_path + suffix
            if os.path.exists(path):
                os.remove(path)

        self._initialize_db()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
