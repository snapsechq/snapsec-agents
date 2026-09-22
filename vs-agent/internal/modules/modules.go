package modules

type Module interface {
	Name() string
	Gather() (interface{}, error)
}
