rule Plex2Shell_Codec_Loader_XMRig_Variant
{
    meta:
        description = "Plex2Shell zz*.so codec-cache loader that deploys XMRig via plex_deploy.sh (cron 'plex_deploy_bootstrap' variant)"
        reference   = "https://github.com/John-NN/plex2shell-xmrig-variant"
        date        = "2026-10-28"
        hash1 = "5a006b1059104180198e2488c54d53f048ae79acc5e67762cb308c13257c7a94"
        hash2 = "edab20185f73dd8aff3dace3e552d4cc07bb16583ef7b9cdec02d81d1d1e52fe"
        hash3 = "046a9efb637f66be75f85a4748742520390382566e1c0a8b34f38ec166e39b5b"
    strings:
        $s1 = "plex_deploy.sh" ascii
        $s2 = "plex_deploy_bootstrap" ascii
        $s3 = ".pxcfg_" ascii
        $s4 = "NOSCRIPT" ascii
        $s5 = "PLEX_PROXY_ONLY" ascii
        $s6 = "HTTP::Tiny" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 2MB and $s1 and 2 of ($s2, $s3, $s4, $s5, $s6)
}

rule Plex2Shell_Persistence_Scripts
{
    meta:
        description = "Watchdog/launcher shell scripts of the Plex2Shell XMRig variant (/var/tmp/.pxwd.sh, .pxagent.sh)"
        date        = "2026-10-28"
    strings:
        $a1 = "/var/tmp/.pxwd.pid" ascii
        $a2 = "/var/tmp/.pxagent.sh" ascii
        $a3 = "/var/tmp/.pxalive" ascii
        $a4 = "Plex Media Server/Cache/PlexMediaScanner" ascii
        $a5 = "plex_exp_proxy.json" ascii
    condition:
        filesize < 20KB and 2 of them
}
