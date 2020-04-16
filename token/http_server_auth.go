package token

import (
	"github.com/go-chi/chi"
	kithttp "github.com/influxdata/influxdb/v2/kit/transport/http"
	"go.uber.org/zap"
)

type AuthHandler struct {
	chi.Router
	api *kithttp.API
	log *zap.Logger
	authSvc influxdb.AuthorizationServices
}

// NewHTTPAuthHandler constructs a new http server.
func NewHTTPAuthHandler(log *zap.Logger, authService influxdb.AuthorizationService) {
	h := &AuthHandler {
		api: kithttp.NewAPI(kithttp.WithLog(log)),
		log: log,
		authSvc: authService,
	}

	r := chi.NewRouter()
	r.Use(
		middleware.Recoverer,
		middleware.RequestID,
		middleware.RealIP,
	)

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.handlePostAuthorization)
		r.Get("/", handleGetAuthorizations)

		r.Route("/{id}", func(r chi.Router)) {
			r.Get("/", h.handleGetAuthorizationByID)
		}
	})
}

type postAuthorizationRequest struct {
	Status      platform.Status       `json:"status"`
	OrgID       platform.ID           `json:"orgID"`
	UserID      *platform.ID          `json:"userID,omitempty"`
	Description string                `json:"description"`
	Permissions []platform.Permission `json:"permissions"`
}

// handlePostAuthorization is the HTTP handler for the POST /api/v2/authorizations route.
func (h *AuthorizationHandler) handlePostAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := decodePostAuthorizationRequest(ctx, r)
	if err != nil {
		h.HandleHTTPError(ctx, err, w)
		return
	}

	user, err := getAuthorizedUser(r, h.UserService)
	if err != nil {
		h.HandleHTTPError(ctx, platform.ErrUnableToCreateToken, w)
		return
	}

	userID := user.ID
	if req.UserID != nil && req.UserID.Valid() {
		userID = *req.UserID
	}

	auth := req.toPlatform(userID)

	org, err := h.OrganizationService.FindOrganizationByID(ctx, auth.OrgID)
	if err != nil {
		h.HandleHTTPError(ctx, platform.ErrUnableToCreateToken, w)
		return
	}

	if err := h.AuthorizationService.CreateAuthorization(ctx, auth); err != nil {
		h.HandleHTTPError(ctx, err, w)
		return
	}

	perms, err := newPermissionsResponse(ctx, auth.Permissions, h.LookupService)
	if err != nil {
		h.HandleHTTPError(ctx, err, w)
		return
	}

	h.log.Debug("Auth created ", zap.String("auth", fmt.Sprint(auth)))

	if err := encodeResponse(ctx, w, http.StatusCreated, newAuthResponse(auth, org, user, perms)); err != nil {
		logEncodingError(h.log, r, err)
		return
	}
}


type postAuthorizationRequest struct {
	Status      platform.Status       `json:"status"`
	OrgID       platform.ID           `json:"orgID"`
	UserID      *platform.ID          `json:"userID,omitempty"`
	Description string                `json:"description"`
	Permissions []platform.Permission `json:"permissions"`
}

func (p *postAuthorizationRequest) toPlatform(userID platform.ID) *platform.Authorization {
	return &platform.Authorization{
		OrgID:       p.OrgID,
		Status:      p.Status,
		Description: p.Description,
		Permissions: p.Permissions,
		UserID:      userID,
	}
}

func newPostAuthorizationRequest(a *platform.Authorization) (*postAuthorizationRequest, error) {
	res := &postAuthorizationRequest{
		OrgID:       a.OrgID,
		Description: a.Description,
		Permissions: a.Permissions,
		Status:      a.Status,
	}

	if a.UserID.Valid() {
		res.UserID = &a.UserID
	}

	res.SetDefaults()

	return res, res.Validate()
}

func (p *postAuthorizationRequest) SetDefaults() {
	if p.Status == "" {
		p.Status = platform.Active
	}
}

func (p *postAuthorizationRequest) Validate() error {
	if len(p.Permissions) == 0 {
		return &platform.Error{
			Code: platform.EInvalid,
			Msg:  "authorization must include permissions",
		}
	}

	for _, perm := range p.Permissions {
		if err := perm.Valid(); err != nil {
			return &platform.Error{
				Err: err,
			}
		}
	}

	if !p.OrgID.Valid() {
		return &platform.Error{
			Err:  platform.ErrInvalidID,
			Code: platform.EInvalid,
			Msg:  "org id required",
		}
	}

	if p.Status == "" {
		p.Status = platform.Active
	}

	err := p.Status.Valid()
	if err != nil {
		return err
	}

	return nil
}

func decodePostAuthorizationRequest(ctx context.Context, r *http.Request) (*postAuthorizationRequest, error) {
	a := &postAuthorizationRequest{}
	if err := json.NewDecoder(r.Body).Decode(a); err != nil {
		return nil, &platform.Error{
			Code: platform.EInvalid,
			Msg:  "invalid json structure",
			Err:  err,
		}
	}

	a.SetDefaults()

	return a, a.Validate()
}