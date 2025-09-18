package model

// PaginationRequest
type PaginationRequest struct {
	Page     int `json:"page" form:"page" binding:"min=1" example:"1"`
	PageSize int `json:"pageSize" form:"pageSize" binding:"min=1,max=100" example:"10"`
}

// PaginationResponse
type PaginationResponse struct {
	Page       int   `json:"page" example:"1"`
	PageSize   int   `json:"pageSize" example:"10"`
	Total      int64 `json:"total" example:"100"`
	TotalPages int   `json:"totalPages" example:"10"`
	HasNext    bool  `json:"hasNext" example:"true"`
	HasPrev    bool  `json:"hasPrev" example:"false"`
}

// PaginationResult
type PaginationResult[T any] struct {
	Data       *[]T               `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
}
