using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.DependencyInjection;
using System.IO;
using System.Net;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", async (HttpContext context) =>
{
    var filePath = context.Request.Query["path"].ToString();
    if (string.IsNullOrEmpty(filePath))
    {
        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await context.Response.WriteAsync("File path is required.");
        return;
    }
    filePath = WebUtility.UrlDecode(filePath);
    var safeBaseDirectory = Path.Combine(Directory.GetCurrentDirectory(), "upload");
    if (!Directory.Exists(safeBaseDirectory))
    {
        Directory.CreateDirectory(safeBaseDirectory);
    }
    var fullPath = Path.GetFullPath(Path.Combine(safeBaseDirectory, filePath));
    if (!fullPath.StartsWith(safeBaseDirectory))
    {
        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await context.Response.WriteAsync("Invalid file path.");
        return;
    }
    try
    {
        var provider = new Microsoft.AspNetCore.StaticFiles.FileExtensionContentTypeProvider();

        var contentType = "";
        if (!provider.TryGetContentType(fullPath, out contentType))
        {
            contentType = "application/octet-stream"; // fallback content type
        }
        context.Response.ContentType = contentType;
        if (!contentType.StartsWith("image/"))
        {
            context.Response.Headers.Add("Content-Disposition", $"attachment; filename=\"{fullPath}\"");
        }
        context.Response.Headers.Add("Content-Security-Policy", "default-src 'none';");
        await context.Response.SendFileAsync(fullPath);
    }
    catch (FileNotFoundException)
    {
        context.Response.StatusCode = (int)HttpStatusCode.NotFound;
        await context.Response.WriteAsync("File not found");
    }
    catch (Exception)
    {
        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
        await context.Response.WriteAsync("An error occurred");
    }
});


app.MapPost("/upload", async (HttpContext context) =>
{
    if (!context.Request.HasFormContentType || !context.Request.Form.Files.Any())
    {
        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await context.Response.WriteAsync("No files uploaded.");
        return;
    }

    var file = context.Request.Form.Files[0];

    const long maxUploadFileSize = 10 * 1024 * 1024; // 10 MB

    if (file.Length > maxUploadFileSize)
    {
        context.Response.StatusCode = (int)HttpStatusCode.RequestEntityTooLarge;
        await context.Response.WriteAsync("Uploaded file size exceeds the allowed limit.");
        return;
    }

    var userFilename = Path.GetFileName(context.Request.Form["filename"].ToString());
    if (string.IsNullOrWhiteSpace(userFilename))
    {
        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        await context.Response.WriteAsync("Invalid file name.");
        return;
    }

    var safeUploadDirectory = Path.Combine(Directory.GetCurrentDirectory(), "upload");

    if (!Directory.Exists(safeUploadDirectory))
    {
        Directory.CreateDirectory(safeUploadDirectory);
    }

    // Combine the sanitized filename with the upload directory
    var uploadPath = Path.Combine(safeUploadDirectory, userFilename);

    try
    {
        // Check that the resolved path is within the allowed directory (prevents path traversal)
        if (!uploadPath.StartsWith(safeUploadDirectory))
        {
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            await context.Response.WriteAsync("Invalid file path.");
            return;
        }

        // Save the uploaded file to the secure upload directory
        using var stream = new FileStream(uploadPath, FileMode.Create);
        await file.CopyToAsync(stream);

        context.Response.StatusCode = (int)HttpStatusCode.OK;
        await context.Response.WriteAsync(uploadPath);
    }
    catch (Exception)
    {
        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
        await context.Response.WriteAsync("An error occurred");
    }
});

app.Run();

