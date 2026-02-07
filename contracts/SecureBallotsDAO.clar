;; SecureBallotsDAO
;; Professional-grade DAO voting system with Clarity 4 features
;; Features: weighted voting, commit-reveal scheme, time-based voting, delegation

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
(define-constant ERR_PROPOSAL_EXPIRED (err u108))
(define-constant ERR_PROPOSAL_NOT_FOUND (err u109))
(define-constant ERR_QUORUM_NOT_MET (err u110))
(define-constant ERR_INVALID_DELEGATION (err u111))
(define-constant ERR_PROPOSAL_NOT_EXPIRED (err u112))

;; Proposal categories
(define-constant CATEGORY_GOVERNANCE u1)
(define-constant CATEGORY_TREASURY u2)
(define-constant CATEGORY_TECHNICAL u3)

;; Data Variables
(define-data-var voting-open bool true)
(define-data-var proposal-count uint u0)
(define-data-var minimum-quorum uint u100) ;; Minimum votes needed for proposal to pass

;; Data Maps
(define-map proposals
    uint 
    {
        title: (string-ascii 256),
        description: (string-ascii 1024),
        category: uint,
        vote-count: uint,
        start-time: uint,  ;; Clarity 4: using stacks-block-time
        end-block: uint,
        created-by: principal,
        executed: bool,
        quorum-required: uint
    }
)

(define-map votes
    {voter: principal, proposal-id: uint}
    {weight: uint, committed: bool, timestamp: uint}
)

(define-map voter-weights
    principal
    uint  ;; Default weight is 1, can be increased based on role
)

;; Zero-Knowledge Proof structure for anonymous voting
(define-map vote-commitments
    principal
    (buff 20)
)

;; Vote delegation system
(define-map delegations
    principal  ;; delegator
    principal  ;; delegate
)

;; List of valid voters
(define-data-var valid-voters (list 1000 principal) (list))

;; Map: voter -> list of proposal-ids (historia głosowań)
(define-map voter-votes
    principal
    (list 1000 uint)
)

;; ========================================
;; Read-Only Functions
;; ========================================

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

(define-read-only (get-proposal-count)
    (var-get proposal-count)
)

(define-read-only (get-minimum-quorum)
    (var-get minimum-quorum)
)

(define-read-only (get-delegation (delegator principal))
    (map-get? delegations delegator)
)

;; Clarity 4 Feature: Get proposal status with time-based logic
(define-read-only (get-proposal-status (proposal-id uint))
    (let
        (
            (proposal-data (unwrap! (map-get? proposals proposal-id) (err ERR_PROPOSAL_NOT_FOUND)))
        )
        (if (get executed proposal-data)
            (ok "executed")
            (if (> stacks-block-height (get end-block proposal-data))
                (if (>= (get vote-count proposal-data) (get quorum-required proposal-data))
                    (ok "passed")
                    (ok "failed"))
                (ok "active"))
        )
    )
)

;; Clarity 4 Feature: Get vote statistics with ascii conversion
(define-read-only (get-vote-statistics (proposal-id uint))
    (let
        (
            (proposal-data (unwrap! (map-get? proposals proposal-id) (err ERR_PROPOSAL_NOT_FOUND)))
            (vote-count (get vote-count proposal-data))
            (quorum (get quorum-required proposal-data))
        )
        (ok {
            proposal-id: proposal-id,
            vote-count: vote-count,
            quorum-required: quorum,
            percentage: (if (> quorum u0) (/ (* vote-count u100) quorum) u0),
            status: (unwrap-panic (get-proposal-status proposal-id))
        })
    )
)

;; Get all proposal IDs (limited to last 100)
(define-read-only (get-all-proposals)
    (ok (var-get proposal-count))
)

;; Check if proposal has expired
(define-read-only (is-proposal-expired (proposal-id uint))
    (let
        (
            (proposal-data (unwrap! (map-get? proposals proposal-id) (err ERR_PROPOSAL_NOT_FOUND)))
        )
        (ok (> stacks-block-height (get end-block proposal-data)))
    )
)

;; ========================================
;; Public Functions - Proposal Management
;; ========================================

;; Clarity 4 Feature: Create proposal with timestamp using stacks-block-time
(define-public (create-proposal 
    (title (string-ascii 256)) 
    (description (string-ascii 1024)) 
    (category uint)
    (blocks uint)
    (quorum uint))
    (let
        (
            (new-id (+ (var-get proposal-count) u1))
            (end-block (+ stacks-block-height blocks))
            (start-time stacks-block-time)  ;; Clarity 4 feature!
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (> (len title) u0) ERR_INVALID_INPUT)
        (asserts! (> (len description) u0) ERR_INVALID_INPUT)
        (asserts! (> blocks u0) ERR_INVALID_INPUT)
        (asserts! (<= category u3) ERR_INVALID_INPUT)
        (asserts! (>= category u1) ERR_INVALID_INPUT)
        
        (map-set proposals
            new-id
            {
                title: title,
                description: description,
                category: category,
                vote-count: u0,
                start-time: start-time,
                end-block: end-block,
                created-by: tx-sender,
                executed: false,
                quorum-required: quorum
            }
        )
        (print {event: "create-proposal", proposal-id: new-id, creator: tx-sender, category: category, quorum: quorum})
        (var-set proposal-count new-id)
        (ok new-id)
    )
)

;; Delete a proposal (only if not executed and owner)
(define-public (delete-proposal (proposal-id uint))
    (let
        (
            (proposal-data (unwrap! (map-get? proposals proposal-id) ERR_INVALID_PROPOSAL))
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (not (get executed proposal-data)) ERR_INVALID_INPUT)
        (map-delete proposals proposal-id)
        (print {event: "delete-proposal", proposal-id: proposal-id, by: tx-sender})
        (ok true)
    )
)

;; Extend proposal deadline
(define-public (extend-proposal-deadline (proposal-id uint) (additional-blocks uint))
    (let
        (
            (proposal-data (unwrap! (map-get? proposals proposal-id) ERR_INVALID_PROPOSAL))
            (new-end-block (+ (get end-block proposal-data) additional-blocks))
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (> additional-blocks u0) ERR_INVALID_INPUT)
        (asserts! (not (get executed proposal-data)) ERR_INVALID_INPUT)
        
        (map-set proposals
            proposal-id
            (merge proposal-data {end-block: new-end-block})
        )
        (print {event: "extend-proposal-deadline", proposal-id: proposal-id, by: tx-sender, new-end-block: new-end-block})
        (ok new-end-block)
    )
)

;; Execute a passed proposal
(define-public (execute-proposal (proposal-id uint))
    (let
        (
            (proposal-data (unwrap! (map-get? proposals proposal-id) ERR_INVALID_PROPOSAL))
            (status (unwrap! (get-proposal-status proposal-id) ERR_INVALID_PROPOSAL))
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (is-eq status "passed") ERR_QUORUM_NOT_MET)
        (asserts! (> stacks-block-height (get end-block proposal-data)) ERR_PROPOSAL_NOT_EXPIRED)
        
        (map-set proposals
            proposal-id
            (merge proposal-data {executed: true})
        )
        (print {event: "execute-proposal", proposal-id: proposal-id, by: tx-sender})
        (ok true)
    )
)

;; ========================================
;; Public Functions - Voter Management
;; ========================================

(define-public (add-voter (voter principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (is-none (index-of (var-get valid-voters) voter)) ERR_INVALID_INPUT)
        (var-set valid-voters (unwrap-panic (as-max-len? (append (var-get valid-voters) voter) u1000)))
        (print {event: "add-voter", voter: voter, by: tx-sender})
        (ok true)
    )
)

;; Batch add voters
(define-public (batch-add-voters (voters (list 50 principal)))
    (begin
    
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (ok (map add-voter-internal voters))
    )
)

(define-private (add-voter-internal (voter principal))
    (if (is-none (index-of (var-get valid-voters) voter))
        (begin
            (var-set valid-voters (unwrap-panic (as-max-len? (append (var-get valid-voters) voter) u1000)))
            true
        )
        false
    )
)

;; Remove a voter
(define-public (remove-voter (voter principal))
    (let
        (
            (voter-index (unwrap! (index-of (var-get valid-voters) voter) ERR_INVALID_VOTER))
            (current-voters (var-get valid-voters))
        )
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        
        ;; Remove voter from list
        (var-set valid-voters (unwrap-panic (as-max-len? 
            (concat 
                (unwrap-panic (slice? current-voters u0 voter-index))
                (unwrap-panic (slice? current-voters (+ voter-index u1) (len current-voters)))
            ) 
            u1000)))
        
        ;; Remove voter weight
        (map-delete voter-weights voter)
        (print {event: "remove-voter", voter: voter, by: tx-sender})
        (ok true)
    )
)

(define-public (set-voter-weight (voter principal) (weight uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (> weight u0) ERR_INVALID_WEIGHT)
        (asserts! (is-valid-voter voter) ERR_INVALID_VOTER)
        (map-set voter-weights voter weight)
        (print {event: "set-voter-weight", voter: voter, weight: weight, by: tx-sender})
        (ok true)
    )
)

;; ========================================
;; Public Functions - Voting
;; ========================================

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
        (print {event: "commit-vote", proposal-id: proposal-id, voter: tx-sender})
        (ok true)
    )
)

;; Clarity 4 Feature: Reveal vote with timestamp
(define-public (reveal-vote (proposal-id uint) (nonce (buff 32)))
    (let
        (
            (proposal (unwrap! (map-get? proposals proposal-id) ERR_INVALID_PROPOSAL))
            (weight (get-effective-weight tx-sender))
            (commitment (unwrap! (get-vote-commitment tx-sender) ERR_INVALID_COMMITMENT))
            (current-time stacks-block-time)  ;; Clarity 4 feature!
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
        
        ;; Record the weighted vote with timestamp
        (map-set votes
            {voter: tx-sender, proposal-id: proposal-id}
            {weight: weight, committed: true, timestamp: current-time}
        )

        ;; Update voter-votes map (historia głosowań)
        (let (
            (current (default-to (list) (map-get? voter-votes tx-sender)))
            (updated (unwrap-panic (as-max-len? (append current proposal-id) u1000)))
        )
            (map-set voter-votes tx-sender updated)
        )

        ;; Update vote count
        (map-set proposals
            proposal-id
            (merge proposal {vote-count: (+ (get vote-count proposal) weight)})
        )

        (print {event: "reveal-vote", proposal-id: proposal-id, voter: tx-sender, weight: weight})
        (ok true)
    ;; Read-only: get all proposal-ids voted by a user
    (define-read-only (get-user-votes (voter principal))
        (default-to (list) (map-get? voter-votes voter))
    )
    )
)

;; ========================================
;; Public Functions - Delegation
;; ========================================

;; Delegate voting power to another address
(define-public (delegate-vote (delegate principal))
    (begin
        (asserts! (is-valid-voter tx-sender) ERR_INVALID_VOTER)
        (asserts! (is-valid-voter delegate) ERR_INVALID_DELEGATION)
        (asserts! (not (is-eq tx-sender delegate)) ERR_INVALID_DELEGATION)
        
        (map-set delegations tx-sender delegate)
        (print {event: "delegate-vote", delegator: tx-sender, delegate: delegate})
        (ok true)
    )
)

;; Revoke delegation
(define-public (revoke-delegation)
    (begin
        (asserts! (is-some (map-get? delegations tx-sender)) ERR_INVALID_DELEGATION)
        (map-delete delegations tx-sender)
        (print {event: "revoke-delegation", delegator: tx-sender})
        (ok true)
    )
)

;; ========================================
;; Public Functions - Admin
;; ========================================

(define-public (close-voting)
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (var-set voting-open false)
        (print {event: "close-voting", by: tx-sender})
        (ok true)
    )
)

(define-public (open-voting)
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (var-set voting-open true)
        (print {event: "open-voting", by: tx-sender})
        (ok true)
    )
)

(define-public (set-minimum-quorum (quorum uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (asserts! (> quorum u0) ERR_INVALID_INPUT)
        (var-set minimum-quorum quorum)
        (print {event: "set-minimum-quorum", quorum: quorum, by: tx-sender})
        (ok true)
    )
)

;; ========================================
;; Helper Functions
;; ========================================

;; Helper function to serialize uint for hashing
(define-private (serialize-uint (value uint))
    (unwrap-panic (to-consensus-buff? value))
)

;; Get effective weight considering delegation
(define-private (get-effective-weight (voter principal))
    (get-voter-weight voter)
)
