CREATE TABLE IF NOT EXISTS "INIT_HASH" (
    "ID" INTEGER primary key,
	"FILE_NAME" TEXT,
	"HASH"  TEXT,
	"SCANED_FLAG" INTEGER,
	"INSERTED_DATE" TEXT,
	"UPDATED_DATE"  TEXT
);
CREATE TABLE IF NOT EXISTS "SCAN_HASH" (
    "ID" INTEGER primary key,
	"FILE_NAME" TEXT,
	"HASH"  TEXT,
	"SCANED_FLAG" INTEGER,
	"INSERTED_DATE" TEXT,
	"UPDATED_DATE"  TEXT
)
