/*
 * Copyright (C) 2025 likme
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

package com.entrechat.app

import android.content.Context
import android.util.Log
import com.entrechat.app.config.NetworkConfig
import com.entrechat.app.crypto.BlobCrypto
import com.entrechat.app.crypto.BlobCryptoImpl
import com.entrechat.app.crypto.CryptoService
import com.entrechat.app.crypto.CryptoServiceImpl
import com.entrechat.app.crypto.KeystorePinDbPassphraseProvider
import com.entrechat.app.crypto.KeyStoreProviderImpl
import com.entrechat.app.crypto.PgpEngineBc
import com.entrechat.app.db.ContactDao
import com.entrechat.app.db.DatabaseFactory
import com.entrechat.app.db.IdentityDao
import com.entrechat.app.db.InviteDao
import com.entrechat.app.db.MessageDao
import com.entrechat.app.identity.IdentityManager
import com.entrechat.app.network.IncomingMessageHandler
import com.entrechat.app.network.IncomingMessageHandlerImpl
import com.entrechat.app.network.LocalHttpJsonClient
import com.entrechat.app.network.LocalMessageServer
import com.entrechat.app.network.MessageRepository
import com.entrechat.app.network.MessageRepositoryRoom
import com.entrechat.app.network.OutgoingMessageSender
import com.entrechat.app.network.ReplayProtection
import com.entrechat.app.network.ReplayProtectionImpl
import com.entrechat.app.network.RemoteMessageClient
import com.entrechat.app.tor.TorManager
import com.entrechat.app.tor.TorManagerImpl
import okhttp3.OkHttpClient
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

object AppGraph {

    @Volatile private var initialized = false

    lateinit var passphraseProvider: KeystorePinDbPassphraseProvider
        private set

    lateinit var blobCrypto: BlobCrypto
        private set

    lateinit var identityDao: IdentityDao
        private set

    lateinit var identityManager: IdentityManager
        private set

    lateinit var contactDao: ContactDao
        private set

    lateinit var messageDao: MessageDao
        private set

    lateinit var inviteDao: InviteDao
        private set

    lateinit var torManager: TorManager
        private set

    lateinit var localHttpClient: LocalHttpJsonClient
        private set

    lateinit var remoteMessageClientDirect: RemoteMessageClient
        private set

    lateinit var localMessageServer: LocalMessageServer
        private set

    lateinit var outgoingSender: OutgoingMessageSender
        private set

    lateinit var db: com.entrechat.app.db.EntrechatDatabase
        private set

    fun requireIdentity() = identityManager.ensureIdentity()

    fun buildTorRemoteClient(socks: TorManager.HostPort): RemoteMessageClient {
        val torOkHttp: OkHttpClient = OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(socks.host, socks.port)))
            .connectTimeout(NetworkConfig.CONNECT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .readTimeout(NetworkConfig.READ_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .writeTimeout(NetworkConfig.WRITE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            .retryOnConnectionFailure(false)
            .build()
        return RemoteMessageClient(torOkHttp)
    }

    fun init(context: Context) {
        if (initialized) return
        synchronized(this) {
            if (initialized) return

            val appContext = context.applicationContext
            Log.i("AppGraph", "init() ENTER")

            passphraseProvider = KeystorePinDbPassphraseProvider(appContext)

            db = DatabaseFactory.get(appContext, passphraseProvider)
            messageDao = db.messageDao()
            contactDao = db.contactDao()
            identityDao = db.identityDao()
            inviteDao = db.inviteDao()

            val messageRepositoryRoom = MessageRepositoryRoom(messageDao)
            val messageRepository: MessageRepository = messageRepositoryRoom

            val replayProtection: ReplayProtection = ReplayProtectionImpl()

            blobCrypto = BlobCryptoImpl(appContext)

            identityManager = IdentityManager(
                identityDao = identityDao,
                blobCrypto = blobCrypto
            )

            val pgpEngine = PgpEngineBc()
            val keyStoreProvider = KeyStoreProviderImpl(
                contactDao = contactDao,
                identityDao = identityDao,
                blobCrypto = blobCrypto
            )

            val cryptoService: CryptoService = CryptoServiceImpl(
                keyStoreProvider = keyStoreProvider,
                pgpEngine = pgpEngine
            )

            val handler: IncomingMessageHandler = IncomingMessageHandlerImpl(
                cryptoService = cryptoService,
                messageRepository = messageRepository,
                replayProtection = replayProtection,
                identityProvider = { requireInitialized(); requireIdentity() },
                contactDao = contactDao,
                requireVerifiedInbound = true,
                appContext = appContext
            )


            torManager = TorManagerImpl(appContext)

            localHttpClient = LocalHttpJsonClient()
            remoteMessageClientDirect = RemoteMessageClient(RemoteMessageClient.buildDefaultClient())

            localMessageServer = LocalMessageServer(
                messageHandler = handler,
                identityProvider = { requireInitialized(); requireIdentity() },
                contactDaoProvider = { requireInitialized(); contactDao },
                messageDaoProvider = { requireInitialized(); messageDao },
                inviteDaoProvider = { requireInitialized(); inviteDao },
                appContext = appContext,
                host = NetworkConfig.LOCAL_HOST,
                port = 0
            )

            outgoingSender = OutgoingMessageSender(
                appContext = appContext,
                identityProvider = { requireInitialized(); requireIdentity() },
                cryptoService = cryptoService,
                localHttpClient = localHttpClient,
                remoteMessageClientDirect = remoteMessageClientDirect,
                remoteMessageClientTor = null,
                torManager = torManager,
                contactDao = contactDao,
                messageRepo = messageRepositoryRoom,
                localServerBaseUrlProvider = {
                    requireInitialized()
                    val p = localMessageServer.getBoundPortOrNull()
                    if (p == null || p <= 0) null else "http://${NetworkConfig.LOCAL_HOST}:$p"
                }
            )

            initialized = true
            Log.i("AppGraph", "init() OK")
        }
    }

    private fun requireInitialized() {
        check(initialized) { "AppGraph not initialized" }
    }
}
