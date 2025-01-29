;; SecureBallotsDAO
;; A secure and transparent voting system with weighted voting capabilities

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_ALREADY_VOTED (err u101))
(define-constant ERR_INVALID_PROPOSAL (err u102))
(define-constant ERR_VOTING_CLOSED (err u103))
(define-constant ERR_INVALID_WEIGHT (err u104))
(define-constant ERR_INVALID_COMMITMENT (err u105))
(define-constant ERR_INVALID_INPUT (err u106))
(define-constant ERR_INVALID_VOTER (err u107))

;; Data Variables
(define-data-var voting-open bool true)
(define-data-var proposal-count uint u0)

;; Data Maps
(define-map proposals
    uint 
    {
        title: (string-ascii 256),
        description: (string-ascii 1024),
        vote-count: uint,
        end-block: uint
    }
)

(define-map votes
    {voter: principal, proposal-id: uint}
    {weight: uint, committed: bool}
)

(define-map voter-weights
    principal
    uint  ;; Default weight is 1, can be increased based on role
)

;; Zero-Knowledge Proof structure for anonymous voting
(define-map vote-commitments
    principal
    (buff 20)  ;; Changed to (buff 20) to match hash160 output
)

;; List of valid voters
(define-data-var valid-voters (list 1000 principal) (list))

;; Read-Only Functions

(define-read-only (get-proposal (proposal-id uint))
    (map-get? proposals proposal-id)
)

(define-read-only (get-voter-weight (voter principal))
    (default-to u1 (map-get? voter-weights voter))
)

(define-read-only (get-vote-commitment (voter principal))
    (map-get? vote-commitments voter)
)

(define-read-only (has-voted (voter principal) (proposal-id uint))
    (default-to 
        false
        (get committed (map-get? votes {voter: voter, proposal-id: proposal-id}))
    )
)

(define-read-only (is-valid-voter (voter principal))
    (is-some (index-of (var-get valid-voters) voter))
)

;; Public Functions

(define-public (create-proposal (title (string-ascii 256)) (description (string-ascii 1024)) (blocks uint))
    (let
        (
            (new-id (+ (var-get proposal-count) u1))
            (end-block (+ stacks-block-height blocks))
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (> (len title) u0) ERR_INVALID_INPUT)
        (asserts! (> (len description) u0) ERR_INVALID_INPUT)
        (asserts! (> blocks u0) ERR_INVALID_INPUT)
        (map-set proposals
            new-id
            {
                title: title,
                description: description,
                vote-count: u0,
                end-block: end-block
            }
        )
        (var-set proposal-count new-id)
        (ok new-id)
    )
)

(define-public (add-voter (voter principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (is-none (index-of (var-get valid-voters) voter)) ERR_INVALID_INPUT)
        (var-set valid-voters (unwrap-panic (as-max-len? (append (var-get valid-voters) voter) u1000)))
        (ok true)
    )
)

(define-public (set-voter-weight (voter principal) (weight uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (> weight u0) ERR_INVALID_WEIGHT)
        (asserts! (is-valid-voter voter) ERR_INVALID_VOTER)
        (map-set voter-weights voter weight)
        (ok true)
    )
)

(define-public (commit-vote (proposal-id uint) (vote-hash (buff 20)))
    (let
        (
            (proposal (unwrap! (map-get? proposals proposal-id) ERR_INVALID_PROPOSAL))
        )
        (asserts! (var-get voting-open) ERR_VOTING_CLOSED)
        (asserts! (<= stacks-block-height (get end-block proposal)) ERR_VOTING_CLOSED)
        (asserts! (not (has-voted tx-sender proposal-id)) ERR_ALREADY_VOTED)
        (asserts! (is-eq (len vote-hash) u20) ERR_INVALID_INPUT)
        (asserts! (is-valid-voter tx-sender) ERR_INVALID_VOTER)
        
        (map-set vote-commitments tx-sender vote-hash)
        (ok true)
    )
)

(define-public (reveal-vote (proposal-id uint) (nonce (buff 32)))
    (let
        (
            (proposal (unwrap! (map-get? proposals proposal-id) ERR_INVALID_PROPOSAL))
            (weight (get-voter-weight tx-sender))
            (commitment (unwrap! (get-vote-commitment tx-sender) ERR_INVALID_COMMITMENT))
        )
        (asserts! (var-get voting-open) ERR_VOTING_CLOSED)
        (asserts! (not (has-voted tx-sender proposal-id)) ERR_ALREADY_VOTED)
        (asserts! (is-valid-voter tx-sender) ERR_INVALID_VOTER)
        
        ;; Verify the vote commitment matches
        (asserts! 
            (is-eq 
                commitment
                (hash160 (concat nonce (serialize-uint proposal-id)))
            )
            ERR_NOT_AUTHORIZED
        )
        
        ;; Record the weighted vote
        (map-set votes
            {voter: tx-sender, proposal-id: proposal-id}
            {weight: weight, committed: true}
        )
        
        ;; Update vote count
        (map-set proposals
            proposal-id
            (merge proposal {vote-count: (+ (get vote-count proposal) weight)})
        )
        
        (ok true)
    )
)

(define-public (close-voting)
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (var-set voting-open false)
        (ok true)
    )
)

;; Helper function to serialize uint for hashing
(define-private (serialize-uint (value uint))
    (unwrap-panic (to-consensus-buff? value))
)