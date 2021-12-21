package cmd

import (
	"archive/zip"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		scanDir()
	},
}

var RootDir string
var tempDirPath = filepath.Join(os.TempDir(), "jndicheck")
var vulnPaths []string

func init() {
	rootCmd.AddCommand(scanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	scanCmd.Flags().StringVarP(&RootDir, "dir", "d", "", "Directory to scan")

	err := scanCmd.MarkFlagRequired("dir")
	if err != nil {
		return
	}

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// scanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func scanDir() {

	if checkFilePath(RootDir) {
		runScanner(RootDir)
	} else {
		log.Fatal("supplied argument is not a directory")
	}
}

func checkFilePath(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func runScanner(dirpath string) {

	start := time.Now()

	err := filepath.Walk(dirpath,

		func(path string, info os.FileInfo, err error) error {

			if err != nil {
				return err
			}

			fmt.Println("Scanning ", path)

			if strings.HasSuffix(info.Name(), ".jar") {
				fmt.Println("Found a Jar-File, extract ", info.Name())
				filenames, _ := openArchive(path)
				fmt.Println("Checking ", info.Name(), " for vulnerability")
				checker(filenames, path)
				return err
			}

			return err
		})

	if err != nil {

		log.Println(err)
	}

	err = os.RemoveAll(tempDirPath)

	fmt.Println()
	fmt.Println("************************* Results of scan *************************")
	fmt.Println("Scan took: ", time.Since(start))

	if len(vulnPaths) > 0 {

		fmt.Println("")
		for _, f := range vulnPaths {
			fmt.Println(f)
		}
	} else {
		fmt.Println("No JndiLookup.class found in ", RootDir)
	}

}

func checker(filenames []string, oName string) {
	for _, f := range filenames {

		if strings.Contains(strings.ToLower(f), "jndilookup.class") {
			vulnPaths = append(vulnPaths, oName)
		}
	}
}

func openArchive(path string) ([]string, error) {

	var filenames []string

	r, err := zip.OpenReader(path)

	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		// Store filename/path for returning and using later on
		fpath := filepath.Join(tempDirPath, f.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(tempDirPath)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}

	return filenames, nil

}
