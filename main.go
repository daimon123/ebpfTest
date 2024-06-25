//package main
//
//import (
//	"fmt"
//	"github.com/coroot/coroot-node-agent/proc"
//	"github.com/spf13/cobra"
//	"github.com/spf13/viper"
//	"github.com/vishvananda/netns"
//	"log"
//	"os"
//	"regexp"
//	"test/namespace"
//)
//
//type Config struct {
//	Database struct {
//		Host     string
//		Port     int
//		User     string
//		Password string
//		Name     string
//	}
//	Server struct {
//		Port int
//	}
//}
//
//type Manager struct {
//	cfgFile string
//	config  Config
//
//	cgroup *Cgroup
//
//	// Namespace
//	selfNetNs         netns.NsHandle
//	hostNetNs         netns.NsHandle
//	hostNetNsId       string
//	agentPid          uint32
//	containerIdRegexp *regexp.Regexp
//}
//
//var Mgr *Manager
//
//var rootCmd = &cobra.Command{
//	Use:   "go_build_test",
//	Short: "test application",
//}
//
//func init() {
//	Mgr = NewManager()
//	cobra.OnInitialize(Mgr.initConfig)
//	rootCmd.PersistentFlags().StringVar(&Mgr.cfgFile, "config", "config.yml", "config file (default is config.yml)")
//	rootCmd.AddCommand(Mgr.NewCmdRun())
//}
//func (mgr *Manager) setNamespace() error {
//	ns, err := namespace.GetSelfNetNs()
//	if err != nil {
//		return fmt.Errorf("Get Self Network Namespace Failed")
//	}
//	mgr.selfNetNs = ns
//
//	hostNetNs, err := namespace.GetHostNetNs()
//	if err != nil {
//		return fmt.Errorf("Get hOST Network Namespace Failed")
//	}
//	mgr.hostNetNs = hostNetNs
//	mgr.hostNetNsId = hostNetNs.UniqueId()
//
//	return nil
//}
//
//func (mgr *Manager) NewCmdRun() *cobra.Command {
//	runCmd := &cobra.Command{
//		Use:   "run",
//		Short: "Run the application",
//		PreRunE: func(cmd *cobra.Command, args []string) error {
//			viper.SetConfigFile(mgr.cfgFile)
//			viper.SetConfigType("yaml")
//
//			if err := viper.ReadInConfig(); err != nil {
//				return fmt.Errorf("Error reading config file, %s", err)
//			}
//
//			if err := viper.Unmarshal(&mgr.config); err != nil {
//				return fmt.Errorf("Unable to decode into struct, %v", err)
//			}
//
//			if mgr.setNamespace() != nil {
//				return fmt.Errorf("Set Namespace Failed ")
//			}
//
//			return nil
//		},
//		RunE: func(cmd *cobra.Command, args []string) error {
//			// Here you would use the configuration values
//			//fmt.Printf("Database Host: %s\n", config.Database.Host)
//
//			err := proc.ExecuteInNetNs(mgr.hostNetNs, mgr.selfNetNs, func() error {
//				if err := TaskstatsInit(); err != nil {
//					return err
//				}
//				return nil
//			})
//
//			if err != nil {
//				return err
//			}
//
//			if namespace.SetCgroupNamespace(mgr.hostNetNs, mgr.selfNetNs) != nil {
//				return fmt.Errorf("Set Cgroup Namespace Failed")
//			}
//
//			fmt.Println("RUN!!!!!!!!!!!!!")
//			return nil
//		},
//	}
//
//	return runCmd
//}
//
//func (mgr *Manager) initConfig() {
//	if mgr.cfgFile != "" {
//		viper.SetConfigFile(mgr.cfgFile)
//	} else {
//		viper.AddConfigPath(".")
//		viper.SetConfigName("config")
//	}
//	viper.AutomaticEnv()
//}
//
//func NewManager() *Manager {
//	cg, err := NewFromProcessCgroupFile("/proc/self/cgroup")
//	if err != nil {
//		return nil
//	}
//	m := &Manager{
//		hostNetNsId: netns.None().UniqueId(),
//		selfNetNs:   netns.None(),
//		agentPid:    uint32(os.Getpid()),
//		cgroup:      cg,
//	}
//	return m
//}
//
//func main() {
//	if err := rootCmd.Execute(); err != nil {
//		log.Fatalf("Error executing root command: %v", err)
//	}
//}

package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
)

type Config struct {
	Database struct {
		Host     string
		Port     int
		User     string
		Password string
		Name     string
	}
	Server struct {
		Port int
	}
}

var (
	cfgFile string
	config  Config
)

var rootCmd = &cobra.Command{
	Use:   "myapp",
	Short: "My application",
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the application",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		viper.SetConfigFile(cfgFile)
		viper.SetConfigType("yaml")

		if err := viper.ReadInConfig(); err != nil {
			return fmt.Errorf("Error reading config file, %s", err)
		}

		if err := viper.Unmarshal(&config); err != nil {
			return fmt.Errorf("Unable to decode into struct, %v", err)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Here you would use the configuration values
		fmt.Printf("Database Host: %s\n", config.Database.Host)
		fmt.Printf("Database Port: %d\n", config.Database.Port)
		fmt.Printf("Database User: %s\n", config.Database.User)
		fmt.Printf("Database Password: %s\n", config.Database.Password)
		fmt.Printf("Database Name: %s\n", config.Database.Name)
		fmt.Printf("Server Port: %d\n", config.Server.Port)

		// Add your application logic here

		return nil
	},
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yml", "config file (default is config.yml)")
	rootCmd.AddCommand(runCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
	}
	viper.AutomaticEnv()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing root command: %v", err)
	}
}
