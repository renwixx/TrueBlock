package com.renwixx.trueadblocker.data

import android.content.Context
import androidx.compose.runtime.Immutable
import androidx.paging.PagingSource
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Transaction
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicLong

const val MODE_EXACT = 0
const val MODE_WILDCARD = 1
const val MODE_REGEX = 2

fun escapeSqlLike(raw: String): String {
	if (raw.isEmpty())
		return ""
	val sb = StringBuilder(raw.length + 4)
	for (c in raw) {
		if (c == '\\' || c == '%' || c == '_')
			sb.append('\\')
		sb.append(c)
	}

	return sb.toString()
}

@Immutable
@Entity(
	tableName = "traffic_agg",
	indices = [
		Index(value = ["lastSeen"]),
		Index(value = ["hitCount"]),
		Index(value = ["isBlocked", "lastSeen"]),
		Index(value = ["isRoute", "lastSeen"]),
	],
)
data class AggregatedLog(
	@PrimaryKey val target: String,
	val isBlocked: Boolean,
	val isRoute: Boolean,
	val hitCount: Long,
	val firstSeen: Long,
	val lastSeen: Long,
	val lastApp: String,
	val lastRule: String,
	val blockedHits: Long = 0L,
	val allowedHits: Long = 0L,
	val cnameHits: Long = 0L,
)

@Immutable
@Entity(
	tableName = "traffic_raw",
	indices = [
		Index(value = ["isBlocked", "id"]),
		Index(value = ["ts"]),
	],
)
data class RawLog(
	@PrimaryKey(autoGenerate = true) val id: Long = 0,
	val target: String,
	val host: String,
	val proto: String,
	val isBlocked: Boolean,
	val appPkg: String,
	val matchedRule: String,
	val ts: Long,
)

@Immutable
@Entity(
	tableName = "custom_rules",
	indices = [
		Index(value = ["pattern", "matchMode", "isAllow"], unique = true),
		Index(value = ["isAllow", "isRoute"]),
	],
)
data class CustomRule(
	@PrimaryKey(autoGenerate = true) val id: Long = 0,
	val pattern: String,
	val matchMode: Int,
	val isAllow: Boolean,
	val isRoute: Boolean,
	val isEnabled: Boolean = true,
	val note: String = "",
	val createdAt: Long = System.currentTimeMillis(),
)

@Entity(tableName = "blocklist_sources")
data class BlocklistSource(
	@PrimaryKey val id: String,
	val title: String,
	val url: String,
	val category: String,
	val desc: String,
	val isHighlight: Boolean,
	val isEnabled: Boolean,
	val ruleCount: Int = 0,
	val routeRuleCount: Int = 0,
	val lastUpdated: Long = 0L,
	val lastError: String = "",
)

@Immutable
@Entity(
	tableName = "tracker_param_stats",
	indices = [
		Index(value = ["removedCount"]),
	],
)
data class TrackerParamStat(
	@PrimaryKey val paramName: String,
	val removedCount: Long,
	val lastHost: String,
	val lastSeen: Long,
)

@Immutable
@Entity(tableName = "traffic_totals")
data class TrafficTotalsEntity(
	@PrimaryKey val id: Int = 1,
	val totalRequests: Long = 0L,
	val totalBlocked: Long = 0L,
	val totalAllowed: Long = 0L,
	val totalCname: Long = 0L,
)

@Immutable
@Entity(tableName = "hourly_traffic_stats")
data class HourlyBucket(
	@PrimaryKey val hourEpoch: Long,
	val blockedCount: Long,
	val allowedCount: Long,
)

@Immutable
@Entity(
	tableName = "app_traffic_stats",
	indices = [
		Index(value = ["totalHits"]),
	],
)
data class AppTrafficStatEntity(
	@PrimaryKey val appPkg: String,
	val totalHits: Long,
	val blockedHits: Long,
	val lastSeen: Long,
)

@Immutable
data class AppTrafficRow(
	val appPkg: String,
	val totalHits: Long,
	val blockedHits: Long,
	val uniqueDomains: Int,
)

data class TrafficSample(
	val target: String,
	val host: String,
	val proto: String,
	val isBlocked: Boolean,
	val isRoute: Boolean,
	val appPkg: String,
	val matchedRule: String,
	val ts: Long = System.currentTimeMillis(),
	val isCname: Boolean = proto == "CNAME",
)

data class TrackerParamSample(
	val paramName: String,
	val host: String,
	val ts: Long = System.currentTimeMillis(),
)

@Dao
interface TrafficDao {
	@Query(
		"""
		SELECT * FROM traffic_agg
		WHERE (:blockFilter = -1 OR isBlocked = :blockFilter)
		AND (:routeMode = -1 OR isRoute = :routeMode)
		AND (:q = '' OR target LIKE '%' || :q || '%' ESCAPE '\')
		ORDER BY lastSeen DESC
		"""
	)
	fun pageRecent(q: String, blockFilter: Int, routeMode: Int): PagingSource<Int, AggregatedLog>

	@Query(
		"""
		SELECT * FROM traffic_agg
		WHERE (:blockFilter = -1 OR isBlocked = :blockFilter)
		AND (:routeMode = -1 OR isRoute = :routeMode)
		AND (:q = '' OR target LIKE '%' || :q || '%' ESCAPE '\')
		ORDER BY hitCount DESC, lastSeen DESC
		"""
	)
	fun pageTop(q: String, blockFilter: Int, routeMode: Int): PagingSource<Int, AggregatedLog>

	@Query(
		"""
		SELECT * FROM traffic_raw
		WHERE (:blockFilter = -1 OR isBlocked = :blockFilter)
		AND (:isRoutesOnly = 0 OR target LIKE '%/%')
		AND (:q = '' OR target LIKE '%' || :q || '%' ESCAPE '\' OR appPkg LIKE '%' || :q || '%' ESCAPE '\')
		ORDER BY id DESC
		"""
	)
	fun pageRaw(q: String, blockFilter: Int, isRoutesOnly: Int = 0): PagingSource<Int, RawLog>

	@Query("SELECT * FROM traffic_agg WHERE target = :target LIMIT 1")
	suspend fun getAggByTarget(target: String): AggregatedLog?

	@Query(
		"""
		INSERT INTO traffic_agg (
			target, isBlocked, isRoute, hitCount, firstSeen, lastSeen, lastApp, lastRule,
			blockedHits, allowedHits, cnameHits
		)
		VALUES (
			:target, :isBlocked, :isRoute, :delta, :firstSeen, :lastSeen, :lastApp, :lastRule,
			:blockedDelta, :allowedDelta, :cnameDelta
		)
		ON CONFLICT(target) DO UPDATE SET
			hitCount = hitCount + :delta,
			blockedHits = blockedHits + :blockedDelta,
			allowedHits = allowedHits + :allowedDelta,
			cnameHits = cnameHits + :cnameDelta,
			lastSeen = MAX(lastSeen, :lastSeen),
			isBlocked = :isBlocked,
			isRoute = :isRoute,
			lastApp = CASE
				WHEN :lastApp != '' AND :lastApp != 'System DNS' THEN :lastApp
				WHEN lastApp = '' THEN :lastApp
				ELSE lastApp
			END,
			lastRule = :lastRule
		"""
	)
	suspend fun upsertAgg(
		target: String,
		isBlocked: Boolean,
		isRoute: Boolean,
		delta: Long,
		blockedDelta: Long,
		allowedDelta: Long,
		cnameDelta: Long,
		firstSeen: Long,
		lastSeen: Long,
		lastApp: String,
		lastRule: String,
	)

	@Query(
		"""
		INSERT INTO traffic_totals (id, totalRequests, totalBlocked, totalAllowed, totalCname)
		VALUES (1, :reqDelta, :blockedDelta, :allowedDelta, :cnameDelta)
		ON CONFLICT(id) DO UPDATE SET
			totalRequests = MAX(0, totalRequests + :reqDelta),
			totalBlocked = MAX(0, totalBlocked + :blockedDelta),
			totalAllowed = MAX(0, totalAllowed + :allowedDelta),
			totalCname = MAX(0, totalCname + :cnameDelta)
		"""
	)
	suspend fun addGlobalTotals(
		reqDelta: Long,
		blockedDelta: Long,
		allowedDelta: Long,
		cnameDelta: Long,
	)

	@Query(
		"""
		INSERT INTO hourly_traffic_stats (hourEpoch, blockedCount, allowedCount)
		VALUES (:hourEpoch, :blockedDelta, :allowedDelta)
		ON CONFLICT(hourEpoch) DO UPDATE SET
			blockedCount = blockedCount + :blockedDelta,
			allowedCount = allowedCount + :allowedDelta
		"""
	)
	suspend fun upsertHourlyBucket(hourEpoch: Long, blockedDelta: Long, allowedDelta: Long)

	@Query(
		"""
		INSERT INTO app_traffic_stats (appPkg, totalHits, blockedHits, lastSeen)
		VALUES (:appPkg, :totalDelta, :blockedDelta, :lastSeen)
		ON CONFLICT(appPkg) DO UPDATE SET
			totalHits = totalHits + :totalDelta,
			blockedHits = blockedHits + :blockedDelta,
			lastSeen = MAX(lastSeen, :lastSeen)
		"""
	)
	suspend fun upsertAppStat(appPkg: String, totalDelta: Long, blockedDelta: Long, lastSeen: Long)

	@Insert(onConflict = OnConflictStrategy.IGNORE)
	suspend fun insertRawBatch(items: List<RawLog>)

	@Transaction
	suspend fun flushSamples(
		aggItems: Collection<AggBatchItem>,
		hourlyItems: Collection<HourlyBatchItem>,
		appItems: Collection<AppBatchItem>,
		rawItems: List<RawLog>,
		totalReqDelta: Long,
		totalBlockedDelta: Long,
		totalAllowedDelta: Long,
		totalCnameDelta: Long,
	) {
		for (item in aggItems) {
			upsertAgg(
				target = item.target,
				isBlocked = item.isBlocked,
				isRoute = item.isRoute,
				delta = item.delta,
				blockedDelta = item.blockedDelta,
				allowedDelta = item.allowedDelta,
				cnameDelta = item.cnameDelta,
				firstSeen = item.firstSeen,
				lastSeen = item.lastSeen,
				lastApp = item.lastApp,
				lastRule = item.lastRule,
			)
		}
		if (totalReqDelta > 0L)
			addGlobalTotals(totalReqDelta, totalBlockedDelta, totalAllowedDelta, totalCnameDelta)
		for (hb in hourlyItems)
			upsertHourlyBucket(hb.hourEpoch, hb.blockedDelta, hb.allowedDelta)
		for (ab in appItems)
			upsertAppStat(ab.appPkg, ab.totalDelta, ab.blockedDelta, ab.lastSeen)
		if (rawItems.isNotEmpty())
			insertRawBatch(rawItems)
	}

	@Query(
		"""
		DELETE FROM traffic_raw
		WHERE id <= COALESCE(
			(SELECT id FROM traffic_raw ORDER BY id DESC LIMIT 1 OFFSET :maxRows),
			-1
		)
		"""
	)
	suspend fun trimRaw(maxRows: Int)

	@Query("DELETE FROM hourly_traffic_stats WHERE hourEpoch < :minHourEpoch")
	suspend fun trimHourlyBefore(minHourEpoch: Int)

	@Query("SELECT COUNT(*) FROM traffic_agg")
	suspend fun countAgg(): Int

	@Query(
		"""
		DELETE FROM traffic_agg
		WHERE target IN (
			SELECT target FROM traffic_agg
			ORDER BY lastSeen ASC
			LIMIT :deleteCount
		)
		"""
	)
	suspend fun trimOldestAgg(deleteCount: Int)

	@Query("SELECT * FROM traffic_totals WHERE id = 1 LIMIT 1")
	fun observeTotalsEntity(): Flow<TrafficTotalsEntity?>

	fun observeTotalRequests(): Flow<Long> = observeTotalsEntity().map { it?.totalRequests ?: 0L }

	fun observeTotalBlocked(): Flow<Long> = observeTotalsEntity().map { it?.totalBlocked ?: 0L }

	fun observeTotalAllowed(): Flow<Long> = observeTotalsEntity().map { it?.totalAllowed ?: 0L }

	fun observeTotalCnameUncloaked(): Flow<Long> = observeTotalsEntity().map { it?.totalCname ?: 0L }

	@Query(
		"""
		SELECT hourEpoch, blockedCount, allowedCount
		FROM hourly_traffic_stats
		WHERE hourEpoch >= (:sinceTs / 3600000)
		ORDER BY hourEpoch ASC
		"""
	)
	suspend fun getHourlyActivity(sinceTs: Long): List<HourlyBucket>

	@Query(
		"""
		SELECT
			s.appPkg AS appPkg,
			s.totalHits AS totalHits,
			s.blockedHits AS blockedHits,
			(SELECT COUNT(*) FROM traffic_agg a WHERE a.lastApp = s.appPkg) AS uniqueDomains
		FROM app_traffic_stats s
		WHERE s.appPkg != '' AND s.appPkg != 'System DNS'
		ORDER BY s.totalHits DESC
		LIMIT :limit
		"""
	)
	suspend fun getTopAppsBreakdown(limit: Int = 30): List<AppTrafficRow>

	@Query("DELETE FROM traffic_agg")
	suspend fun clearAgg()

	@Query("DELETE FROM traffic_raw")
	suspend fun clearRaw()

	@Query("DELETE FROM traffic_totals")
	suspend fun clearTotals()

	@Query("DELETE FROM hourly_traffic_stats")
	suspend fun clearHourly()

	@Query("DELETE FROM app_traffic_stats")
	suspend fun clearAppStats()

	@Transaction
	suspend fun clearAllTraffic() {
		clearAgg()
		clearRaw()
		clearTotals()
		clearHourly()
		clearAppStats()
	}

	@Query("SELECT * FROM app_traffic_stats WHERE appPkg = :pkg LIMIT 1")
	suspend fun getAppStat(pkg: String): AppTrafficStatEntity?

	@Query("DELETE FROM app_traffic_stats WHERE appPkg = :pkg")
	suspend fun deleteAppStat(pkg: String)

	@Query("UPDATE traffic_agg SET lastApp = '' WHERE lastApp = :pkg AND hitCount > :appTotalHits")
	suspend fun detachSharedAggApp(pkg: String, appTotalHits: Long)

	@Query("DELETE FROM traffic_agg WHERE lastApp = :pkg")
	suspend fun deleteAggByApp(pkg: String)

	@Query("DELETE FROM traffic_raw WHERE appPkg = :pkg")
	suspend fun deleteRawByApp(pkg: String)

	@Transaction
	suspend fun deleteAllByApp(pkg: String) {
		val st = getAppStat(pkg)
		if (st != null) {
			val allowed = (st.totalHits - st.blockedHits).coerceAtLeast(0L)
			addGlobalTotals(-st.totalHits, -st.blockedHits, -allowed, 0L)
			detachSharedAggApp(pkg, st.totalHits)
			deleteAppStat(pkg)
		}
		deleteRawByApp(pkg)
		deleteAggByApp(pkg)
	}
}

data class AggBatchItem(
	val target: String,
	var isBlocked: Boolean,
	var isRoute: Boolean,
	var delta: Long,
	var blockedDelta: Long,
	var allowedDelta: Long,
	var cnameDelta: Long,
	var firstSeen: Long,
	var lastSeen: Long,
	var lastApp: String,
	var lastRule: String,
)

data class HourlyBatchItem(
	val hourEpoch: Long,
	var blockedDelta: Long,
	var allowedDelta: Long,
)

data class AppBatchItem(
	val appPkg: String,
	var totalDelta: Long,
	var blockedDelta: Long,
	var lastSeen: Long,
)

@Dao
interface TrackerParamDao {
	@Query(
		"""
		INSERT INTO tracker_param_stats (paramName, removedCount, lastHost, lastSeen)
		VALUES (:paramName, :delta, :lastHost, :lastSeen)
		ON CONFLICT(paramName) DO UPDATE SET
			removedCount = removedCount + :delta,
			lastHost = :lastHost,
			lastSeen = MAX(lastSeen, :lastSeen)
		"""
	)
	suspend fun upsertParamStat(paramName: String, delta: Long, lastHost: String, lastSeen: Long)

	@Transaction
	suspend fun upsertBatch(items: Collection<ParamBatchItem>) {
		for (item in items)
			upsertParamStat(item.paramName, item.delta, item.lastHost, item.lastSeen)
	}

	@Query("SELECT COALESCE(SUM(removedCount), 0) FROM tracker_param_stats")
	fun observeTotalRemoved(): Flow<Long>

	@Query("SELECT * FROM tracker_param_stats ORDER BY removedCount DESC LIMIT 100")
	fun observeTopParams(): Flow<List<TrackerParamStat>>

	@Query("DELETE FROM tracker_param_stats")
	suspend fun clearAll()
}

data class ParamBatchItem(
	val paramName: String,
	var delta: Long,
	var lastHost: String,
	var lastSeen: Long,
)

@Dao
interface RuleDao {
	@Query(
		"""
		SELECT * FROM custom_rules
		WHERE (:q = '' OR pattern LIKE '%' || :q || '%' ESCAPE '\' OR note LIKE '%' || :q || '%' ESCAPE '\')
		ORDER BY createdAt DESC
		"""
	)
	fun pageAllRules(q: String): PagingSource<Int, CustomRule>

	@Query(
		"""
		SELECT * FROM custom_rules
		WHERE isAllow = :isAllow
		AND (:isRoutesOnly = 0 OR isRoute = 1)
		AND (:q = '' OR pattern LIKE '%' || :q || '%' ESCAPE '\' OR note LIKE '%' || :q || '%' ESCAPE '\')
		ORDER BY createdAt DESC
		"""
	)
	fun pageRules(isAllow: Boolean, isRoutesOnly: Int, q: String): PagingSource<Int, CustomRule>

	@Query(
		"""
		SELECT * FROM custom_rules
		WHERE isRoute = 1
		AND (:q = '' OR pattern LIKE '%' || :q || '%' ESCAPE '\' OR note LIKE '%' || :q || '%' ESCAPE '\')
		ORDER BY createdAt DESC
		"""
	)
	fun pageRouteRules(q: String): PagingSource<Int, CustomRule>

	@Query("SELECT * FROM custom_rules WHERE isEnabled = 1")
	fun observeEnabled(): Flow<List<CustomRule>>

	@Query("SELECT * FROM custom_rules WHERE isEnabled = 1")
	suspend fun getEnabled(): List<CustomRule>

	@Query("SELECT * FROM custom_rules ORDER BY createdAt DESC")
	suspend fun getAll(): List<CustomRule>

	@Insert(onConflict = OnConflictStrategy.REPLACE)
	suspend fun upsert(rule: CustomRule): Long

	@Insert(onConflict = OnConflictStrategy.REPLACE)
	suspend fun upsertAll(rules: List<CustomRule>)

	@Query("UPDATE custom_rules SET isEnabled = :isEnabled WHERE id = :id")
	suspend fun setEnabled(id: Long, isEnabled: Boolean)

	@Query("DELETE FROM custom_rules WHERE id = :id")
	suspend fun deleteById(id: Long)

	@Query("DELETE FROM custom_rules WHERE pattern = :pattern AND isAllow = :isAllow")
	suspend fun deleteByPattern(pattern: String, isAllow: Boolean)

	@Query("DELETE FROM custom_rules")
	suspend fun clearAll()
}

@Dao
interface BlocklistDao {
	@Query("SELECT * FROM blocklist_sources ORDER BY isHighlight DESC, title ASC")
	fun observeAll(): Flow<List<BlocklistSource>>

	@Query("SELECT * FROM blocklist_sources")
	suspend fun getAll(): List<BlocklistSource>

	@Query("SELECT * FROM blocklist_sources WHERE isEnabled = 1")
	suspend fun getEnabled(): List<BlocklistSource>

	@Insert(onConflict = OnConflictStrategy.IGNORE)
	suspend fun insertIgnore(items: List<BlocklistSource>)

	@Insert(onConflict = OnConflictStrategy.REPLACE)
	suspend fun upsert(item: BlocklistSource)

	@Query("UPDATE blocklist_sources SET isEnabled = :isEnabled WHERE id = :id")
	suspend fun setEnabled(id: String, isEnabled: Boolean)

	@Query(
		"""
		UPDATE blocklist_sources
		SET ruleCount = :ruleCount, routeRuleCount = :routeCount, lastUpdated = :ts, lastError = :err
		WHERE id = :id
		"""
	)
	suspend fun updateStats(id: String, ruleCount: Int, routeCount: Int, ts: Long, err: String)

	@Query("DELETE FROM blocklist_sources WHERE id = :id")
	suspend fun deleteById(id: String)

	@Query("DELETE FROM blocklist_sources WHERE id IN (:ids)")
	suspend fun deleteByIds(ids: List<String>)
}

private val MIGRATION_1_2 = object : Migration(1, 2) {
	override fun migrate(db: SupportSQLiteDatabase) {
		db.execSQL(
			"""
			CREATE TABLE IF NOT EXISTS `tracker_param_stats` (
				`paramName` TEXT NOT NULL,
				`removedCount` INTEGER NOT NULL,
				`lastHost` TEXT NOT NULL,
				`lastSeen` INTEGER NOT NULL,
				PRIMARY KEY(`paramName`)
			)
			""".trimIndent()
		)
		db.execSQL("CREATE INDEX IF NOT EXISTS `index_tracker_param_stats_removedCount` ON `tracker_param_stats` (`removedCount`)")
	}
}

private val MIGRATION_2_3 = object : Migration(2, 3) {
	override fun migrate(db: SupportSQLiteDatabase) {
		db.execSQL("ALTER TABLE `traffic_agg` ADD COLUMN `blockedHits` INTEGER NOT NULL DEFAULT 0")
		db.execSQL("ALTER TABLE `traffic_agg` ADD COLUMN `allowedHits` INTEGER NOT NULL DEFAULT 0")
		db.execSQL("ALTER TABLE `traffic_agg` ADD COLUMN `cnameHits` INTEGER NOT NULL DEFAULT 0")
		db.execSQL(
			"""
			UPDATE `traffic_agg` SET
				`blockedHits` = CASE WHEN `isBlocked` = 1 THEN `hitCount` ELSE 0 END,
				`allowedHits` = CASE WHEN `isBlocked` = 0 THEN `hitCount` ELSE 0 END,
				`cnameHits` = CASE WHEN `lastRule` LIKE 'CNAME (%' THEN `hitCount` ELSE 0 END
			""".trimIndent()
		)
		db.execSQL("CREATE INDEX IF NOT EXISTS `index_traffic_raw_ts` ON `traffic_raw` (`ts`)")
		db.execSQL(
			"""
			CREATE TABLE IF NOT EXISTS `traffic_totals` (
				`id` INTEGER NOT NULL,
				`totalRequests` INTEGER NOT NULL,
				`totalBlocked` INTEGER NOT NULL,
				`totalAllowed` INTEGER NOT NULL,
				`totalCname` INTEGER NOT NULL,
				PRIMARY KEY(`id`)
			)
			""".trimIndent()
		)
		db.execSQL(
			"""
			INSERT OR REPLACE INTO `traffic_totals` (`id`, `totalRequests`, `totalBlocked`, `totalAllowed`, `totalCname`)
			SELECT
				1,
				COALESCE(SUM(`hitCount`), 0),
				COALESCE(SUM(`blockedHits`), 0),
				COALESCE(SUM(`allowedHits`), 0),
				COALESCE(SUM(`cnameHits`), 0)
			FROM `traffic_agg`
			""".trimIndent()
		)
		db.execSQL(
			"""
			CREATE TABLE IF NOT EXISTS `hourly_traffic_stats` (
				`hourEpoch` INTEGER NOT NULL,
				`blockedCount` INTEGER NOT NULL,
				`allowedCount` INTEGER NOT NULL,
				PRIMARY KEY(`hourEpoch`)
			)
			""".trimIndent()
		)
		db.execSQL(
			"""
			INSERT OR REPLACE INTO `hourly_traffic_stats` (`hourEpoch`, `blockedCount`, `allowedCount`)
			SELECT
				(`ts` / 3600000) AS `h`,
				SUM(CASE WHEN `isBlocked` = 1 THEN 1 ELSE 0 END),
				SUM(CASE WHEN `isBlocked` = 0 THEN 1 ELSE 0 END)
			FROM `traffic_raw`
			GROUP BY `h`
			""".trimIndent()
		)
		db.execSQL(
			"""
			CREATE TABLE IF NOT EXISTS `app_traffic_stats` (
				`appPkg` TEXT NOT NULL,
				`totalHits` INTEGER NOT NULL,
				`blockedHits` INTEGER NOT NULL,
				`lastSeen` INTEGER NOT NULL,
				PRIMARY KEY(`appPkg`)
			)
			""".trimIndent()
		)
		db.execSQL("CREATE INDEX IF NOT EXISTS `index_app_traffic_stats_totalHits` ON `app_traffic_stats` (`totalHits`)")
		db.execSQL(
			"""
			INSERT OR REPLACE INTO `app_traffic_stats` (`appPkg`, `totalHits`, `blockedHits`, `lastSeen`)
			SELECT
				`lastApp`,
				SUM(`hitCount`),
				SUM(`blockedHits`),
				MAX(`lastSeen`)
			FROM `traffic_agg`
			WHERE `lastApp` != '' AND `lastApp` != 'System DNS'
			GROUP BY `lastApp`
			""".trimIndent()
		)
	}
}

@Database(
	entities = [
		AggregatedLog::class,
		RawLog::class,
		CustomRule::class,
		BlocklistSource::class,
		TrackerParamStat::class,
		TrafficTotalsEntity::class,
		HourlyBucket::class,
		AppTrafficStatEntity::class,
	],
	version = 3,
	exportSchema = false,
)
abstract class AppDatabase : RoomDatabase() {
	abstract fun trafficDao(): TrafficDao
	abstract fun ruleDao(): RuleDao
	abstract fun blocklistDao(): BlocklistDao
	abstract fun trackerParamDao(): TrackerParamDao

	companion object {
		@Volatile
		private var _instance: AppDatabase? = null

		fun get(ctx: Context): AppDatabase {
			_instance?.let { return it }

			return synchronized(this) {
				_instance ?: Room.databaseBuilder(
					ctx.applicationContext,
					AppDatabase::class.java,
					"true_adblocker.db",
				)
					.addMigrations(MIGRATION_1_2, MIGRATION_2_3)
					.setJournalMode(JournalMode.WRITE_AHEAD_LOGGING)
					.fallbackToDestructiveMigrationOnDowngrade()
					.build()
					.also { _instance = it }
			}
		}
	}
}

class TrafficPipeline(
	private val _dao: TrafficDao,
	private val _paramDao: TrackerParamDao,
	private val _prefs: AppPrefs,
) {
	private val _scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
	private val _queue = Channel<TrafficSample>(
		capacity = 8192,
		onBufferOverflow = BufferOverflow.DROP_OLDEST,
	)
	private val _paramQueue = Channel<TrackerParamSample>(
		capacity = 4096,
		onBufferOverflow = BufferOverflow.DROP_OLDEST,
	)
	private val _clearEpoch = AtomicLong(0L)
	private var _flushCounter = 0

	init {
		_scope.launch {
			val batch = ArrayList<TrafficSample>(256)
			while (isActive) {
				val first = _queue.receive()
				val epochBefore = _clearEpoch.get()
				batch.clear()
				batch.add(first)

				val cfg = _prefs.state.value
				val waitMs = cfg.logFlushIntervalMs.coerceIn(50, 5000).toLong()
				val maxBatch = cfg.logMaxBatchSize.coerceIn(32, 4096)

				delay(waitMs)
				while (batch.size < maxBatch) {
					val next = _queue.tryReceive().getOrNull() ?: break
					batch.add(next)
				}

				if (_clearEpoch.get() != epochBefore)
					continue
				persistBatch(batch, epochBefore)
			}
		}

		_scope.launch {
			val pBatch = HashMap<String, ParamBatchItem>(32)
			while (isActive) {
				val first = _paramQueue.receive()
				pBatch.clear()
				pBatch[first.paramName] = ParamBatchItem(first.paramName, 1L, first.host, first.ts)

				delay(500)
				while (true) {
					val next = _paramQueue.tryReceive().getOrNull() ?: break
					val cur = pBatch[next.paramName]
					if (cur == null) {
						pBatch[next.paramName] = ParamBatchItem(next.paramName, 1L, next.host, next.ts)
					} else {
						cur.delta += 1L
						cur.lastHost = next.host
						if (next.ts > cur.lastSeen)
							cur.lastSeen = next.ts
					}
				}

				runCatching { _paramDao.upsertBatch(pBatch.values) }
			}
		}
	}

	fun push(sample: TrafficSample) {
		if (_prefs.state.value.isAppBypassed(sample.appPkg))
			return
		_queue.trySend(sample)
	}

	fun pushRemovedParams(host: String, params: List<String>) {
		val now = System.currentTimeMillis()
		for (p in params)
			_paramQueue.trySend(TrackerParamSample(p.lowercase(), host, now))
	}

	suspend fun clearAll() {
		_clearEpoch.incrementAndGet()
		while (_queue.tryReceive().isSuccess) {
			// Drain queued samples before clearing DB tables
		}
		_dao.clearAllTraffic()
	}

	private suspend fun persistBatch(samples: List<TrafficSample>, expectedEpoch: Long) {
		val aggMap = HashMap<String, AggBatchItem>(samples.size)
		val hourlyMap = HashMap<Long, HourlyBatchItem>(4)
		val appMap = HashMap<String, AppBatchItem>(16)
		val rawList = ArrayList<RawLog>(samples.size)
		val cfg = _prefs.state.value

		var totalReqDelta = 0L
		var totalBlockedDelta = 0L
		var totalAllowedDelta = 0L
		var totalCnameDelta = 0L

		for (s in samples) {
			if (cfg.isAppBypassed(s.appPkg))
				continue

			val bDelta = if (s.isBlocked) 1L else 0L
			val aDelta = if (s.isBlocked) 0L else 1L
			val cDelta = if (s.isCname) 1L else 0L

			totalReqDelta += 1L
			totalBlockedDelta += bDelta
			totalAllowedDelta += aDelta
			totalCnameDelta += cDelta

			val existing = aggMap[s.target]
			if (existing == null) {
				aggMap[s.target] = AggBatchItem(
					target = s.target,
					isBlocked = s.isBlocked,
					isRoute = s.isRoute,
					delta = 1L,
					blockedDelta = bDelta,
					allowedDelta = aDelta,
					cnameDelta = cDelta,
					firstSeen = s.ts,
					lastSeen = s.ts,
					lastApp = s.appPkg,
					lastRule = s.matchedRule,
				)
			} else {
				existing.delta += 1L
				existing.blockedDelta += bDelta
				existing.allowedDelta += aDelta
				existing.cnameDelta += cDelta
				if (s.ts > existing.lastSeen) {
					existing.lastSeen = s.ts
					existing.isBlocked = s.isBlocked
					existing.lastRule = s.matchedRule
				}
				if (s.ts < existing.firstSeen)
					existing.firstSeen = s.ts
				existing.isRoute = existing.isRoute || s.isRoute
				if (s.appPkg.isNotEmpty() && s.appPkg != "System DNS")
					existing.lastApp = s.appPkg
				else if (existing.lastApp.isEmpty())
					existing.lastApp = s.appPkg
			}

			val hour = s.ts / 3_600_000L
			val hb = hourlyMap[hour]
			if (hb == null) {
				hourlyMap[hour] = HourlyBatchItem(hour, bDelta, aDelta)
			} else {
				hb.blockedDelta += bDelta
				hb.allowedDelta += aDelta
			}

			if (s.appPkg.isNotEmpty() && s.appPkg != "System DNS") {
				val ab = appMap[s.appPkg]
				if (ab == null) {
					appMap[s.appPkg] = AppBatchItem(s.appPkg, 1L, bDelta, s.ts)
				} else {
					ab.totalDelta += 1L
					ab.blockedDelta += bDelta
					if (s.ts > ab.lastSeen)
						ab.lastSeen = s.ts
				}
			}

			if (cfg.isRawLoggingEnabled) {
				rawList.add(
					RawLog(
						target = s.target,
						host = s.host,
						proto = s.proto,
						isBlocked = s.isBlocked,
						appPkg = s.appPkg,
						matchedRule = s.matchedRule,
						ts = s.ts,
					)
				)
			}
		}

		if (totalReqDelta == 0L || _clearEpoch.get() != expectedEpoch)
			return

		runCatching {
			_dao.flushSamples(
				aggItems = aggMap.values,
				hourlyItems = hourlyMap.values,
				appItems = appMap.values,
				rawItems = rawList,
				totalReqDelta = totalReqDelta,
				totalBlockedDelta = totalBlockedDelta,
				totalAllowedDelta = totalAllowedDelta,
				totalCnameDelta = totalCnameDelta,
			)
			_flushCounter++
			if (_flushCounter % 25 == 0) {
				if (cfg.isRawLoggingEnabled)
					_dao.trimRaw(cfg.maxRawEntries)
				val minHour = ((System.currentTimeMillis() / 3_600_000L) - 72L).toInt()
				_dao.trimHourlyBefore(minHour)
				val count = _dao.countAgg()
				if (count > cfg.maxAggEntries)
					_dao.trimOldestAgg((count - cfg.maxAggEntries) + 1000)
			}
		}
	}
}
