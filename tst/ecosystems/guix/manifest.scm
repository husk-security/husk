;; manifest.scm — a GNU Guix package manifest.
;; Pass to: guix shell -m manifest.scm   (or `guix package -m manifest.scm`)
;;
;; Versions here are OPTIONAL; the real version pin is the channel git commit
;; in channels.scm, not the @version. Most real manifests list bare names.

(specifications->manifest
 (list "git@2.41.0"                 ; full pinned version
       "python@3.10"                ; partial version prefix (means 3.10.x)
       "ripgrep"                    ; unversioned (the common case)
       "gcc-toolchain@12:lib"       ; version + output -> coordinate gcc-toolchain@12
       "git:send-email"             ; same name, different output -> distinct entry
       "emacs-vterm"
       "font-adobe-source-code-pro"
       ;; Decoy strings below must NOT be treated as packages:
       ;; "https://git.savannah.gnu.org/git/guix.git" is a channel URL.
       "node@20.11"))
