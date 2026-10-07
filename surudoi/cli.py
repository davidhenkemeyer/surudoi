"""Command-line maintenance: `flask --app surudoi <command>`."""
from pathlib import Path

import click

from .auth import normalize_email
from .models import ROLE_ADMIN, ROLE_STORE_ADMIN, ROLES, Store, User, db
from .stores import decode_csv_bytes, export_stores, geocode_missing, import_stores


def init_app(app):
    @app.cli.command("import-stores")
    @click.argument("csv_path", type=click.Path(exists=True, dir_okay=False))
    @click.option("--no-geocode", is_flag=True, help="Don't look up map coordinates for new addresses.")
    def import_stores_cmd(csv_path, no_geocode):
        """Create/update stores from a CSV file (matched by store name)."""
        result = import_stores(decode_csv_bytes(Path(csv_path).read_bytes()), geocode=not no_geocode)
        click.echo(f"Done: {result.summary}.")
        for e in result.errors:
            click.echo(f"  ! {e}")
        if result.not_located:
            click.echo("  Not found on the map: " + ", ".join(result.not_located))

    @app.cli.command("export-stores")
    @click.argument("csv_path", type=click.Path(dir_okay=False))
    def export_stores_cmd(csv_path):
        """Write all stores to a CSV file (re-importable)."""
        Path(csv_path).write_text(export_stores(), encoding="utf-8", newline="")
        click.echo(f"Wrote {Store.query.count()} stores to {csv_path}.")

    @app.cli.command("geocode-stores")
    def geocode_stores_cmd():
        """Look up map coordinates for stores that don't have any."""
        found, missing = geocode_missing()
        click.echo(f"Located {found} store(s).")
        if missing:
            click.echo("Still missing: " + ", ".join(missing))

    @app.cli.command("add-user")
    @click.argument("email")
    @click.option("--role", type=click.Choice(list(ROLES)), default=ROLE_ADMIN, show_default=True)
    @click.option("--store", "store_ref", help="Store name or id (required for store_admin).")
    @click.option("--name", default="")
    def add_user_cmd(email, role, store_ref, name):
        """Create a user, or update the role of an existing one."""
        normalized = normalize_email(email)
        if not normalized:
            raise click.BadParameter("not a valid email address", param_hint="EMAIL")
        store = None
        if store_ref:
            store = (db.session.get(Store, int(store_ref)) if store_ref.isdigit()
                     else Store.query.filter(db.func.lower(Store.name) == store_ref.lower()).first())
            if store is None:
                raise click.BadParameter(f"no store matching {store_ref!r}", param_hint="--store")
        if role == ROLE_STORE_ADMIN and store is None:
            raise click.UsageError("--store is required for store admins")
        user = User.query.filter_by(email=normalized).first() or User(email=normalized)
        user.role = role
        user.store_id = store.id if role == ROLE_STORE_ADMIN else None
        user.name = name or user.name or ""
        user.blocked = False
        db.session.add(user)
        db.session.commit()
        where = f" for {store.name}" if user.store_id else ""
        click.echo(f"{normalized} is now a {ROLES[role].lower()}{where}.")
