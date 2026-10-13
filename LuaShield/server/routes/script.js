const Database = new (require("../modules/database"))();
const { readFile } = require("node:fs/promises");
const path = require("node:path");

async function routes(fastify) {
    fastify.get("/:project/:id", async (request, reply) => {
        const { project, id } = request.params;
        if (!/^[a-zA-Z0-9-]{1,80}$/.test(project) || !/^[a-zA-Z0-9-]{1,80}$/.test(id)) {
            return reply.code(400).send("Invalid script identifier");
        }
        const Project = await Database.GetProject(project);
        const Script = await Database.GetScript(project, id);
        if (!Project || !Project.Online || !Script || !/^v\d+\.\d+\.\d+$/.test(Script.Version)) {
            return reply.code(404).send("Script unavailable");
        }
        const File = path.join(__dirname, "../../files/projects", project, id, `${Script.Version}.lua`);
        try {
            const Source = await readFile(File, "utf8");
            return reply.header("Cache-Control", "no-store")
                .type("text/plain; charset=utf-8").send(Source);
        } catch (Error) {
            if (Error.code === "ENOENT") return reply.code(404).send("Script unavailable");
            throw Error;
        }
    });
}

module.exports = routes;
